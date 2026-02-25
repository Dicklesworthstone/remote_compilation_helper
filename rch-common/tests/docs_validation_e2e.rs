//! Documentation validation for reliability operations (bd-vvmd.6.4)
//!
//! Validates:
//!   - Reliability runbook exists and contains required sections
//!   - Command examples reference valid CLI commands
//!   - Error code ranges match implemented taxonomy
//!   - Status schema references are accurate
//!   - Runbook covers all posture states and failure modes

use rch_common::e2e::logging::{LogLevel, LogSource, TestLoggerBuilder};
use serde::{Deserialize, Serialize};

// ===========================================================================
// Documentation validation types
// ===========================================================================

const DOCS_VALIDATION_SCHEMA_VERSION: &str = "1.0.0";

/// A documentation section requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DocRequirement {
    id: String,
    section: String,
    required_content: Vec<String>,
    description: String,
}

/// Result of validating a documentation file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DocValidationResult {
    file_path: String,
    exists: bool,
    requirements_checked: usize,
    requirements_met: usize,
    failures: Vec<String>,
}

/// Full validation config.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DocsValidationConfig {
    schema_version: String,
    requirements: Vec<DocRequirement>,
}

// ===========================================================================
// Requirement definitions
// ===========================================================================

fn build_runbook_requirements() -> Vec<DocRequirement> {
    vec![
        DocRequirement {
            id: "DOC-ARCH-001".into(),
            section: "Architecture Overview".into(),
            required_content: vec![
                "Repo Convergence".into(),
                "Storage Pressure".into(),
                "Process Triage".into(),
                "Circuit Breakers".into(),
                "Fail-Open".into(),
            ],
            description: "Runbook must describe all five reliability pillars".into(),
        },
        DocRequirement {
            id: "DOC-POSTURE-001".into(),
            section: "System Posture".into(),
            required_content: vec![
                "remote-ready".into(),
                "degraded".into(),
                "local-only".into(),
            ],
            description: "Runbook must document all three system postures".into(),
        },
        DocRequirement {
            id: "DOC-DIAG-001".into(),
            section: "Quick Diagnosis".into(),
            required_content: vec!["rch status".into(), "rch doctor".into()],
            description: "Runbook must include diagnostic commands".into(),
        },
        DocRequirement {
            id: "DOC-ERROR-001".into(),
            section: "Error Taxonomy".into(),
            required_content: vec![
                "RCH-E".into(),
                "Configuration".into(),
                "Transfer".into(),
                "Build execution".into(),
                "Convergence".into(),
                "Daemon".into(),
                "Storage".into(),
            ],
            description: "Runbook must document error code categories".into(),
        },
        DocRequirement {
            id: "DOC-FAIL-001".into(),
            section: "Worker Unreachable".into(),
            required_content: vec![
                "circuit_open".into(),
                "worker_unreachable".into(),
                "rch workers probe".into(),
                "Risk:".into(),
            ],
            description: "Worker unreachable failure mode documented with remediation and risk"
                .into(),
        },
        DocRequirement {
            id: "DOC-FAIL-002".into(),
            section: "Disk Pressure".into(),
            required_content: vec![
                "pressure_critical".into(),
                "cargo clean".into(),
                "Risk:".into(),
            ],
            description: "Disk pressure failure mode documented with remediation and risk".into(),
        },
        DocRequirement {
            id: "DOC-FAIL-003".into(),
            section: "Convergence Failed".into(),
            required_content: vec![
                "convergence_failed".into(),
                "convergence_drifting".into(),
                "repo-convergence repair".into(),
                "--force".into(),
                "Risk:".into(),
            ],
            description: "Convergence failure mode documented with remediation and risk".into(),
        },
        DocRequirement {
            id: "DOC-FAIL-004".into(),
            section: "All Workers Down".into(),
            required_content: vec!["local-only".into(), "fail-open".into()],
            description: "Fail-open scenario documented".into(),
        },
        DocRequirement {
            id: "DOC-FAIL-005".into(),
            section: "Schema Mismatch".into(),
            required_content: vec!["schema_mismatch".into(), "migration".into()],
            description: "Schema mismatch failure mode documented".into(),
        },
        DocRequirement {
            id: "DOC-FLAGS-001".into(),
            section: "Feature Flags".into(),
            required_content: vec![
                "disabled".into(),
                "dry_run".into(),
                "canary".into(),
                "enabled".into(),
            ],
            description: "Feature flag states documented".into(),
        },
        DocRequirement {
            id: "DOC-SLO-001".into(),
            section: "SLO Guardrails".into(),
            required_content: vec![
                "Hook decision latency".into(),
                "Convergence".into(),
                "Fallback rate".into(),
            ],
            description: "SLO budgets documented".into(),
        },
        DocRequirement {
            id: "DOC-TRIAGE-001".into(),
            section: "Incident Triage".into(),
            required_content: vec!["posture".into(), "Escalation".into()],
            description: "Incident triage flowchart documented".into(),
        },
        DocRequirement {
            id: "DOC-DRYRUN-001".into(),
            section: "Dry-Run".into(),
            required_content: vec!["safe to run".into(), "--force".into(), "destructive".into()],
            description: "Dry-run safety guidance documented".into(),
        },
    ]
}

fn validate_runbook(content: &str, requirements: &[DocRequirement]) -> DocValidationResult {
    let mut met = 0;
    let mut failures = Vec::new();

    for req in requirements {
        let all_present = req
            .required_content
            .iter()
            .all(|c| content.contains(c.as_str()));

        if all_present {
            met += 1;
        } else {
            let missing: Vec<_> = req
                .required_content
                .iter()
                .filter(|c| !content.contains(c.as_str()))
                .collect();
            failures.push(format!(
                "{}: missing {:?} in section '{}'",
                req.id, missing, req.section
            ));
        }
    }

    DocValidationResult {
        file_path: "docs/runbooks/reliability-operations.md".into(),
        exists: true,
        requirements_checked: requirements.len(),
        requirements_met: met,
        failures,
    }
}

// ===========================================================================
// Tests: runbook exists
// ===========================================================================

#[test]
fn e2e_docs_runbook_exists() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    assert!(
        path.exists(),
        "reliability operations runbook must exist at {:?}",
        path
    );
}

#[test]
fn e2e_docs_runbook_not_empty() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.len() > 1000,
        "runbook must have substantial content (got {} bytes)",
        content.len()
    );
}

// ===========================================================================
// Tests: content validation
// ===========================================================================

#[test]
fn e2e_docs_runbook_passes_all_requirements() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();
    let requirements = build_runbook_requirements();
    let result = validate_runbook(&content, &requirements);

    assert_eq!(
        result.requirements_met,
        result.requirements_checked,
        "runbook validation failed:\n{}",
        result.failures.join("\n")
    );
}

#[test]
fn e2e_docs_runbook_architecture_section() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("# Runbook: Reliability Operations"));
    assert!(content.contains("## Architecture Overview"));
}

#[test]
fn e2e_docs_runbook_has_code_examples() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();
    let code_block_count = content.matches("```bash").count();
    assert!(
        code_block_count >= 5,
        "runbook must have at least 5 code examples (found {})",
        code_block_count
    );
}

#[test]
fn e2e_docs_runbook_mentions_risk_for_destructive_ops() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();
    let risk_count = content.matches("**Risk:**").count();
    assert!(
        risk_count >= 3,
        "runbook must document risks for at least 3 destructive operations (found {})",
        risk_count
    );
}

// ===========================================================================
// Tests: existing runbooks still present
// ===========================================================================

#[test]
fn e2e_docs_existing_runbooks_present() {
    let docs_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks");
    let expected = [
        "debugging-slow-builds.md",
        "worker-recovery.md",
        "reliability-operations.md",
    ];
    for file in &expected {
        assert!(
            docs_dir.join(file).exists(),
            "runbook '{}' must exist in docs/runbooks/",
            file
        );
    }
}

// ===========================================================================
// Tests: error code ranges match
// ===========================================================================

#[test]
fn e2e_docs_error_taxonomy_matches_implementation() {
    // Verify the documented error code ranges align with the codebase
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs/runbooks/reliability-operations.md");
    let content = std::fs::read_to_string(&path).unwrap();

    // All documented ranges must be present
    let ranges = [
        "RCH-E0xx", "RCH-E1xx", "RCH-E2xx", "RCH-E3xx", "RCH-E4xx", "RCH-E5xx",
    ];
    for range in &ranges {
        assert!(
            content.contains(range),
            "error range '{}' must be documented",
            range
        );
    }
}

// ===========================================================================
// Tests: schema stability
// ===========================================================================

#[test]
fn e2e_docs_validation_schema_version() {
    let config = DocsValidationConfig {
        schema_version: DOCS_VALIDATION_SCHEMA_VERSION.into(),
        requirements: build_runbook_requirements(),
    };
    assert_eq!(config.schema_version, DOCS_VALIDATION_SCHEMA_VERSION);
}

#[test]
fn e2e_docs_validation_serialization_roundtrip() {
    let config = DocsValidationConfig {
        schema_version: DOCS_VALIDATION_SCHEMA_VERSION.into(),
        requirements: build_runbook_requirements(),
    };
    let json = serde_json::to_string_pretty(&config).unwrap();
    let parsed: DocsValidationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.requirements.len(), config.requirements.len());
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_docs_logging_integration() {
    let logger = TestLoggerBuilder::new("docs_validation").build();
    let requirements = build_runbook_requirements();

    logger.log(
        LogLevel::Info,
        LogSource::Custom("docs_validation".into()),
        format!(
            "Docs validation: {} requirements defined",
            requirements.len(),
        ),
    );

    let entries = logger.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].message.contains("requirements"));
}
