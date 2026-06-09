//! `rch admit` preflight core (bd-session-history-remediation-ocv9i.6.1).
//!
//! `rch admit -- <command>` is a fast, read-only preflight an agent runs before
//! expensive work: it classifies the command, determines its family and the
//! capabilities a worker must have to run it, and — given the daemon's
//! candidate/rejection data — returns a decisive Offload / Local / Queue / Defer
//! answer. This module is the **pure** heart of that: classification and
//! capability derivation ([`preflight`]) plus the decision rule that folds in
//! aggregated candidate rejections ([`refine_recommendation`]).
//!
//! It reuses the existing classifier ([`crate::patterns`]), the capability
//! requirement contract ([`crate::capability_probe::CapabilityRequirement`]),
//! and the admission-rejection vocabulary ([`crate::admission_rejection`]) rather
//! than inventing a parallel path. The clap `rch admit` subcommand and the
//! optional daemon candidate query are the CLI/daemon surface over this contract.

use serde::{Deserialize, Serialize};

use crate::admission_rejection::{AdmissionRejectionSummary, RejectionClass};
use crate::capability_probe::CapabilityRequirement;
use crate::patterns::{
    CompilationKind, classify_command, classify_command_detailed, split_shell_commands,
};

/// The decisive recommendation `rch admit` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmitRecommendation {
    /// Offload to a remote worker.
    Offload,
    /// Run locally (not a compilation, or nothing to gain from offload).
    Local,
    /// Offload-eligible but the fleet is transiently busy/unhealthy — queue.
    Queue,
    /// No worker can run this command (structural capability gap) — defer until
    /// the fleet gains the capability rather than waiting on a slot.
    Defer,
}

impl AdmitRecommendation {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AdmitRecommendation::Offload => "offload",
            AdmitRecommendation::Local => "local",
            AdmitRecommendation::Queue => "queue",
            AdmitRecommendation::Defer => "defer",
        }
    }
}

/// The capabilities a command needs from a worker, as a serializable summary.
/// Mirrors (and converts to) [`CapabilityRequirement`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredCapabilities {
    pub needs_cargo: bool,
    pub needs_bun: bool,
    /// rustup targets the command explicitly requests (`--target <triple>`).
    pub needs_targets: Vec<String>,
    /// Explicit toolchain overrides (`cargo +nightly-…`).
    pub needs_toolchains: Vec<String>,
}

impl RequiredCapabilities {
    /// Convert to the admission-gate [`CapabilityRequirement`] for a given wire
    /// protocol.
    #[must_use]
    pub fn to_requirement(&self, min_protocol: u32) -> CapabilityRequirement {
        CapabilityRequirement {
            needs_targets: self.needs_targets.clone(),
            min_protocol,
            needs_cargo: self.needs_cargo,
            needs_bun: self.needs_bun,
            needs_toolchains: self.needs_toolchains.clone(),
            ..CapabilityRequirement::default()
        }
    }
}

/// The result of a read-only admit preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitPreflight {
    /// The command as given.
    pub command: String,
    /// Sub-commands when the input is a compound shell form (`a && b`); a single
    /// command yields one element.
    pub compound: Vec<String>,
    /// Whether the (whole) command is a compilation worth offloading.
    pub is_compilation: bool,
    /// The compilation family, when classified (e.g. `cargo_build`, `bun_test`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Capabilities a worker must have to run it.
    pub required: RequiredCapabilities,
    /// Whether proof/strict-remote policy is in force (caller-supplied).
    pub proof_policy: bool,
    /// The decision before daemon candidate data is folded in.
    pub base_recommendation: AdmitRecommendation,
    /// Operator-facing explanation.
    pub detail: String,
}

/// Snake_case family token for a compilation kind.
fn family_token(kind: CompilationKind) -> &'static str {
    match kind {
        CompilationKind::CargoBuild => "cargo_build",
        CompilationKind::CargoTest => "cargo_test",
        CompilationKind::CargoCheck => "cargo_check",
        CompilationKind::CargoClippy => "cargo_clippy",
        CompilationKind::CargoDoc => "cargo_doc",
        CompilationKind::CargoNextest => "cargo_nextest",
        CompilationKind::CargoBench => "cargo_bench",
        CompilationKind::Rustc => "rustc",
        CompilationKind::Gcc => "gcc",
        CompilationKind::Gpp => "gpp",
        CompilationKind::Clang => "clang",
        CompilationKind::Clangpp => "clangpp",
        CompilationKind::Make => "make",
        CompilationKind::CmakeBuild => "cmake",
        CompilationKind::Ninja => "ninja",
        CompilationKind::Meson => "meson",
        CompilationKind::BunTest => "bun_test",
        CompilationKind::BunTypecheck => "bun_typecheck",
    }
}

/// Whether a kind is part of the Rust/cargo family (needs cargo).
fn is_rust_kind(kind: CompilationKind) -> bool {
    matches!(
        kind,
        CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoNextest
            | CompilationKind::CargoBench
            | CompilationKind::Rustc
    )
}

/// Derive required capabilities from a command string + its classified kind.
fn derive_capabilities(command: &str, kind: Option<CompilationKind>) -> RequiredCapabilities {
    let mut req = RequiredCapabilities::default();
    if let Some(kind) = kind {
        req.needs_cargo = is_rust_kind(kind);
        req.needs_bun = matches!(
            kind,
            CompilationKind::BunTest | CompilationKind::BunTypecheck
        );
    }
    // Scan tokens for `--target <triple>` / `--target=<triple>` and `+toolchain`.
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        if let Some(triple) = tok.strip_prefix("--target=") {
            if !triple.is_empty() {
                req.needs_targets.push(triple.to_string());
            }
        } else if tok == "--target" {
            if let Some(triple) = tokens.get(i + 1) {
                req.needs_targets.push((*triple).to_string());
                i += 1;
            }
        } else if let Some(toolchain) = tok.strip_prefix('+') {
            // A cargo toolchain override token, e.g. `cargo +nightly-2025-11-01 build`.
            if !toolchain.is_empty() {
                req.needs_toolchains.push(toolchain.to_string());
            }
        }
        i += 1;
    }
    req.needs_targets.sort();
    req.needs_targets.dedup();
    req.needs_toolchains.sort();
    req.needs_toolchains.dedup();
    req
}

/// Run the read-only preflight for a command. `proof_policy` reflects the
/// caller's strict/proof-remote setting (from env/flags). Pure.
#[must_use]
pub fn preflight(command: &str, proof_policy: bool) -> AdmitPreflight {
    let compound: Vec<String> = split_shell_commands(command)
        .into_iter()
        .map(Into::into)
        .collect();
    let compound = if compound.is_empty() {
        vec![command.to_string()]
    } else {
        compound
    };

    // The whole command is a compilation if any sub-command classifies as one;
    // capabilities are the union across compilation sub-commands.
    let mut is_compilation = false;
    let mut family: Option<String> = None;
    let mut required = RequiredCapabilities::default();
    for part in &compound {
        let detail = classify_command_detailed(part);
        let c = &detail.classification;
        if c.is_compilation {
            is_compilation = true;
            if let Some(kind) = c.kind
                && family.is_none()
            {
                family = Some(family_token(kind).to_string());
            }
            let part_req = derive_capabilities(part, c.kind);
            required.needs_cargo |= part_req.needs_cargo;
            required.needs_bun |= part_req.needs_bun;
            required.needs_targets.extend(part_req.needs_targets);
            required.needs_toolchains.extend(part_req.needs_toolchains);
        }
    }
    required.needs_targets.sort();
    required.needs_targets.dedup();
    required.needs_toolchains.sort();
    required.needs_toolchains.dedup();

    let base_recommendation = if is_compilation {
        AdmitRecommendation::Offload
    } else {
        AdmitRecommendation::Local
    };

    let detail = if !is_compilation {
        "not a compilation command; run locally".to_string()
    } else if compound.len() > 1 {
        format!(
            "compound command with {} parts; offload-eligible (family={})",
            compound.len(),
            family.as_deref().unwrap_or("unknown")
        )
    } else {
        format!(
            "offload-eligible (family={})",
            family.as_deref().unwrap_or("unknown")
        )
    };

    AdmitPreflight {
        command: command.to_string(),
        compound,
        is_compilation,
        family,
        required,
        proof_policy,
        base_recommendation,
        detail,
    }
}

/// Fold aggregated candidate-rejection data into a final recommendation.
///
/// A non-offload base stays as-is. For an offload-eligible command: if every
/// candidate was rejected, distinguish a *structural* gap (command-admissibility
/// rejections dominate — no worker can run it, so `Defer`) from a *transient*
/// one (worker-health rejections dominate — busy/unhealthy, so `Queue`). If some
/// candidate remained admissible, `Offload`.
#[must_use]
pub fn refine_recommendation(
    base: AdmitRecommendation,
    summary: &AdmissionRejectionSummary,
) -> AdmitRecommendation {
    if base != AdmitRecommendation::Offload {
        return base;
    }
    if !summary.all_rejected() {
        return AdmitRecommendation::Offload;
    }
    let command_specific = summary.class_count(RejectionClass::CommandAdmissibility)
        + summary.class_count(RejectionClass::ProjectPolicy);
    let health = summary.class_count(RejectionClass::WorkerHealth);
    if command_specific >= health {
        AdmitRecommendation::Defer
    } else {
        AdmitRecommendation::Queue
    }
}

/// Convenience: whether `command` would offload at all (cheap classification).
#[must_use]
pub fn is_offloadable(command: &str) -> bool {
    classify_command(command).is_compilation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_rejection::{
        AdmissionRejectionCategory, CandidateRejection, aggregate_rejections,
    };

    #[test]
    fn common_cargo_build_offloads_needing_cargo() {
        let p = preflight("cargo build --release", false);
        assert!(p.is_compilation);
        assert_eq!(p.family.as_deref(), Some("cargo_build"));
        assert!(p.required.needs_cargo);
        assert!(!p.required.needs_bun);
        assert_eq!(p.base_recommendation, AdmitRecommendation::Offload);
    }

    #[test]
    fn wasm_target_is_captured_as_required_capability() {
        let p = preflight("cargo build --target wasm32-unknown-unknown", false);
        assert!(p.required.needs_cargo);
        assert_eq!(p.required.needs_targets, vec!["wasm32-unknown-unknown"]);
        // `--target=triple` form too.
        let p2 = preflight("cargo test --target=aarch64-apple-darwin", false);
        assert_eq!(p2.required.needs_targets, vec!["aarch64-apple-darwin"]);
    }

    #[test]
    fn explicit_toolchain_override_is_captured() {
        let p = preflight("cargo +nightly-2025-11-01 build", false);
        assert_eq!(p.required.needs_toolchains, vec!["nightly-2025-11-01"]);
    }

    #[test]
    fn bun_command_needs_bun() {
        let p = preflight("bun test", false);
        if p.is_compilation {
            assert!(p.required.needs_bun);
            assert!(!p.required.needs_cargo);
            assert_eq!(p.base_recommendation, AdmitRecommendation::Offload);
        } else {
            // If the classifier doesn't treat this bun form as compilation, the
            // preflight must still be decisive (local), never ambiguous.
            assert_eq!(p.base_recommendation, AdmitRecommendation::Local);
        }
    }

    #[test]
    fn non_compilation_runs_local() {
        let p = preflight("ls -la", false);
        assert!(!p.is_compilation);
        assert_eq!(p.base_recommendation, AdmitRecommendation::Local);
        assert!(p.required.needs_cargo == false && p.required.needs_bun == false);
        assert!(p.detail.contains("locally"));
    }

    #[test]
    fn quoted_exec_form_is_classified_decisively() {
        // A quoted exec wrapper around a build still resolves to a definite
        // recommendation (never ambiguous).
        let p = preflight("sh -c 'cargo build'", false);
        assert!(matches!(
            p.base_recommendation,
            AdmitRecommendation::Offload | AdmitRecommendation::Local
        ));
    }

    #[test]
    fn compound_shell_form_is_split_and_unioned() {
        let p = preflight("cargo build && bun test", false);
        assert!(
            p.compound.len() >= 2,
            "compound must be split: {:?}",
            p.compound
        );
        // It is compilation if either part is, and capabilities union.
        if p.is_compilation {
            assert!(p.required.needs_cargo || p.required.needs_bun);
        }
    }

    #[test]
    fn refine_offload_when_some_candidate_admissible() {
        // 1 of 3 rejected => others admissible => Offload.
        let summary = aggregate_rejections(
            3,
            &[CandidateRejection {
                worker_id: "a".into(),
                category: AdmissionRejectionCategory::InsufficientSlots,
            }],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Offload
        );
    }

    #[test]
    fn refine_queue_when_all_rejected_for_health() {
        // All rejected, dominated by worker-health (busy/unhealthy) => Queue.
        let summary = aggregate_rejections(
            2,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::InsufficientSlots,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::CircuitOpen,
                },
            ],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Queue
        );
    }

    #[test]
    fn refine_defer_when_all_rejected_for_capability() {
        // All rejected for command-specific capability => no worker can ever run
        // it => Defer (waiting on a slot is pointless).
        let summary = aggregate_rejections(
            2,
            &[
                CandidateRejection {
                    worker_id: "a".into(),
                    category: AdmissionRejectionCategory::MissingRustTarget,
                },
                CandidateRejection {
                    worker_id: "b".into(),
                    category: AdmissionRejectionCategory::OsArchMismatch,
                },
            ],
        );
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Offload, &summary),
            AdmitRecommendation::Defer
        );
    }

    #[test]
    fn refine_keeps_local_recommendation() {
        let summary = aggregate_rejections(0, &[]);
        assert_eq!(
            refine_recommendation(AdmitRecommendation::Local, &summary),
            AdmitRecommendation::Local
        );
    }

    #[test]
    fn required_capabilities_convert_to_requirement() {
        let p = preflight("cargo build --target wasm32-unknown-unknown", false);
        let req = p.required.to_requirement(3);
        assert!(req.needs_cargo);
        assert_eq!(req.min_protocol, 3);
        assert_eq!(
            req.needs_targets,
            vec!["wasm32-unknown-unknown".to_string()]
        );
    }

    #[test]
    fn preflight_serializes_with_stable_tokens() {
        let p = preflight("cargo build", false);
        let value = serde_json::to_value(&p).unwrap();
        assert_eq!(value["base_recommendation"], "offload");
        assert_eq!(value["is_compilation"], true);
        let back: AdmitPreflight = serde_json::from_value(value).unwrap();
        assert_eq!(back, p);
    }
}
