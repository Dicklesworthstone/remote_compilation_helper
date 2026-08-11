//! The shadow decision plane (bead S4 / bridge plan Phase S) — M0's
//! "shadow-only" promise, delivered: every wrapper consult computes a
//! key through the REAL Epic F pipeline (`rabs_key::action_key::
//! compute_action_key` — the same twelve-slot canonical encoding
//! production will use), records a decision receipt, and answers
//! pass-through. Nothing is served; everything is learned.
//!
//! ## Shadow-grade honesty
//!
//! The full descriptor needs input CLOSURES that only exist once
//! Phase 1 lands snapshot-backed execution. The shadow tier therefore
//! fills the closure slots (`action_inputs`, `negative_dependencies`,
//! `dependency_inputs`) with a CONSTANT typed marker digest, so the
//! shadow key is a function of the OBSERVABLE components only: argv,
//! cwd, toolchain identity, environment names, platform, class. A
//! repeat lookup under that key is consequently an UPPER BOUND on
//! would-have-hit — two invocations with identical argv but different
//! file contents shadow-collide — and every receipt says so
//! (`grade: shadow-upper-bound`). The number this plane reports is
//! "at most this many would have hit", never more than the truth.

use rabs_key::action_key::compute_action_key;
use rabs_key::typed_digest::compute;
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::redaction::redact_argv;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

/// What the edge observes about one consult (parsed from the frame).
#[derive(Debug, Clone)]
pub struct ConsultObservation {
    /// Full argv after the wrapper (argv[0] = real tool path).
    pub argv: Vec<String>,
    /// Working directory of the invocation.
    pub cwd: String,
    /// `CARGO_*`/`RUSTC_*` env NAMES present (values stay client-side
    /// in shadow tier; names participate in the key).
    pub env_names: Vec<String>,
}

/// The plane's answer for one consult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowDecision {
    /// Hex of the final action key (shadow grade).
    pub key_hex: String,
    /// Upper-bound would-have-hit (a prior completion shares the key).
    pub would_have_hit_upper_bound: bool,
    /// Classified action class tag (Debug format).
    pub class: String,
}

/// Classify the invocation (shadow heuristics; F-epic classes).
#[must_use]
pub fn classify(argv: &[String]) -> ActionClass {
    let crate_name = argv
        .windows(2)
        .find(|w| w[0] == "--crate-name")
        .map(|w| w[1].as_str());
    if crate_name == Some("build_script_build") {
        return ActionClass::BuildScriptCompile;
    }
    // Registry sources compile from the cargo registry cache; workspace
    // members compile from anywhere else.
    let from_registry = argv
        .iter()
        .any(|a| a.contains("/registry/src/") || a.contains("\\registry\\src\\"));
    if from_registry {
        ActionClass::RustcDependencyCompile
    } else {
        ActionClass::RustcWorkspaceCompile
    }
}

fn constant_component(domain: &'static str) -> rabs_protocol::result_identity::TypedDigest {
    compute(domain, b"shadow-v1:unresolved-until-phase-1")
}

/// Build the shadow-grade descriptor from an observation. Toolchain
/// identity is correlation-grade: the tool path plus its inode
/// size/mtime (read HERE, by the daemon — the wrapper never stats).
#[must_use]
pub fn shadow_descriptor(observation: &ConsultObservation) -> ActionDescriptor {
    let argv_joined = observation.argv.join("\u{1f}");
    let toolchain_identity =
        observation
            .argv
            .first()
            .map_or_else(String::new, |tool| match std::fs::metadata(tool) {
                Ok(meta) => format!("{tool}|len={}|mtime={:?}", meta.len(), meta.modified().ok()),
                Err(_) => format!("{tool}|unstat"),
            });
    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 0, // 0 = shadow projection (upper bound)
        action_class: classify(&observation.argv),
        normalized_invocation: compute(
            "rabs.shadow.normalized-invocation.v1",
            argv_joined.as_bytes(),
        ),
        virtual_working_directory: compute(
            "rabs.shadow.working-directory.v1",
            observation.cwd.as_bytes(),
        ),
        action_inputs: constant_component("rabs.shadow.action-inputs.v1"),
        negative_dependencies: constant_component("rabs.shadow.negative-deps.v1"),
        dependency_inputs: constant_component("rabs.shadow.dependency-inputs.v1"),
        toolchain: compute("rabs.shadow.toolchain.v1", toolchain_identity.as_bytes()),
        output_platform: compute(
            "rabs.shadow.output-platform.v1",
            format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS).as_bytes(),
        ),
        environment: compute(
            "rabs.shadow.environment-names.v1",
            observation.env_names.join("\u{1f}").as_bytes(),
        ),
        sandbox_semantic_policy: constant_component("rabs.shadow.sandbox-policy.v1"),
        build_path_semantic_policy: constant_component("rabs.shadow.path-policy.v1"),
        execution_semantics: constant_component("rabs.shadow.exec-semantics.v1"),
        output_declarations: constant_component("rabs.shadow.output-decls.v1"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The shadow plane: persisted completion index + receipt stream. The
/// index is a SET of seen keys — would-have-hit is presence, not count
/// (a shadow hit is "this key completed before", nothing finer).
#[derive(Debug)]
pub struct ShadowPlane {
    index: BTreeSet<String>,
    index_path: PathBuf,
    receipts_path: PathBuf,
    consults: u64,
}

impl ShadowPlane {
    /// Open (or create) the plane's state under `state_dir`.
    pub fn open(state_dir: &std::path::Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let index_path = state_dir.join("shadow-index.ndjson");
        let receipts_path = state_dir.join("shadow-receipts.ndjson");
        let mut index = BTreeSet::new();
        if let Ok(text) = std::fs::read_to_string(&index_path) {
            for line in text.lines() {
                if let Some(key) = line
                    .strip_prefix("{\"key\":\"")
                    .and_then(|rest| rest.split('"').next())
                {
                    index.insert(key.to_string());
                }
            }
        }
        Ok(Self {
            index,
            index_path,
            receipts_path,
            consults: 0,
        })
    }

    /// Process one consult: REAL key computation, upper-bound lookup,
    /// receipt append, completion recorded (the F discovery cycle in
    /// shadow form: this consult's key becomes next consult's lookup).
    pub fn on_consult(
        &mut self,
        trace: &str,
        observation: &ConsultObservation,
        flight_of: impl FnOnce(&str) -> &'static str,
    ) -> std::io::Result<ShadowDecision> {
        self.consults += 1;
        let descriptor = shadow_descriptor(observation);
        let breakdown = compute_action_key(&descriptor);
        let key_hex = hex(&breakdown.final_key.bytes);
        let flight = flight_of(&key_hex);
        let would_have_hit_upper_bound = self.index.contains(&key_hex);
        let class = format!("{:?}", descriptor.action_class);

        // Receipt first (a crash between receipt and index loses a
        // completion, never a receipt — receipts are the audit trail).
        // argv0 is user-controlled, so it MUST be JSON-escaped: a path
        // carrying a quote/backslash/control byte would otherwise tear
        // the receipt (the INV-4 fault S8 guards against). `trace`,
        // `class`, and `key_hex` are structurally safe (conn id, enum
        // name, hex).
        let argv_redacted = redact_argv(&observation.argv);
        let argv0_json =
            serde_json::to_string(argv_redacted.first().map(String::as_str).unwrap_or(""))
                .unwrap_or_else(|_| "\"\"".to_string());
        let receipt = format!(
            "{{\"v\":1,\"kind\":\"shadow-receipt\",\"trace\":\"{trace}\",\
             \"class\":\"{class}\",\"key\":\"{key_hex}\",\
             \"hit_upper_bound\":{would_have_hit_upper_bound},\
             \"flight\":\"{flight}\",\
             \"grade\":\"shadow-upper-bound\",\"decision\":\"pass-through\",\
             \"argv0\":{argv0_json},\"argc\":{}}}",
            observation.argv.len(),
        );
        append_line(&self.receipts_path, &receipt)?;

        // Record the completion (shadow-observed: pass-through always
        // completes locally). Persist the key only on first sight — the
        // on-disk index is one line per unique key, and the in-memory
        // set mirrors it exactly.
        if !would_have_hit_upper_bound {
            append_line(&self.index_path, &format!("{{\"key\":\"{key_hex}\"}}"))?;
            self.index.insert(key_hex.clone());
        }

        Ok(ShadowDecision {
            key_hex,
            would_have_hit_upper_bound,
            class,
        })
    }

    /// Receipts written by this instance.
    #[must_use]
    pub fn consults(&self) -> u64 {
        self.consults
    }
}

fn append_line(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::options()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}

/// The shadow report: per-class consults and hit-upper-bound counts,
/// straight from the receipt stream (the audit trail is the input —
/// not in-memory state).
pub fn shadow_report(state_dir: &std::path::Path) -> std::io::Result<String> {
    let receipts =
        std::fs::read_to_string(state_dir.join("shadow-receipts.ndjson")).unwrap_or_default();
    let mut per_class: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total = 0u64;
    for line in receipts.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("kind").and_then(|k| k.as_str()) != Some("shadow-receipt") {
            continue;
        }
        total += 1;
        let class = value
            .get("class")
            .and_then(|c| c.as_str())
            .unwrap_or("?")
            .to_string();
        let hit = value
            .get("hit_upper_bound")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let entry = per_class.entry(class).or_insert((0, 0));
        entry.0 += 1;
        if hit {
            entry.1 += 1;
        }
    }
    let mut lines = vec![format!(
        "{{\"v\":1,\"kind\":\"shadow-report\",\"total_consults\":{total},\"grade\":\"shadow-upper-bound\"}}"
    )];
    for (class, (consults, hits)) in per_class {
        lines.push(format!(
            "{{\"class\":\"{class}\",\"consults\":{consults},\"hit_upper_bound\":{hits}}}"
        ));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(argv: &[&str]) -> ConsultObservation {
        ConsultObservation {
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            cwd: "/work".to_string(),
            env_names: vec!["CARGO_HOME".to_string()],
        }
    }

    #[test]
    fn discovery_cycle_first_miss_then_upper_bound_hit_no_smearing() {
        let dir = tempfile::tempdir().unwrap();
        let mut plane = ShadowPlane::open(dir.path()).unwrap();
        let invocation = observation(&["/tc/rustc", "--crate-name", "fx"]);
        let first = plane.on_consult("t1", &invocation, |_| "leader").unwrap();
        assert!(!first.would_have_hit_upper_bound, "first sight = miss");
        let second = plane.on_consult("t2", &invocation, |_| "leader").unwrap();
        assert!(
            second.would_have_hit_upper_bound,
            "repeat = upper-bound hit"
        );
        assert_eq!(first.key_hex, second.key_hex);
        // Different argv MUST NOT smear into a hit.
        let other = plane
            .on_consult(
                "t3",
                &observation(&["/tc/rustc", "--crate-name", "other"]),
                |_| "leader",
            )
            .unwrap();
        assert!(!other.would_have_hit_upper_bound);
        assert_ne!(other.key_hex, first.key_hex);
    }

    #[test]
    fn index_survives_reopen_and_receipts_reconcile_one_to_one() {
        let dir = tempfile::tempdir().unwrap();
        let invocation = observation(&["/tc/rustc", "--crate-name", "fx"]);
        {
            let mut plane = ShadowPlane::open(dir.path()).unwrap();
            plane.on_consult("t1", &invocation, |_| "leader").unwrap();
        }
        // A NEW instance (daemon restart) still knows the completion.
        let mut plane = ShadowPlane::open(dir.path()).unwrap();
        let decision = plane.on_consult("t2", &invocation, |_| "leader").unwrap();
        assert!(decision.would_have_hit_upper_bound, "index persisted");
        // Receipts: exactly one line per consult.
        let receipts = std::fs::read_to_string(dir.path().join("shadow-receipts.ndjson")).unwrap();
        assert_eq!(receipts.lines().count(), 2);
        for line in receipts.lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["grade"], "shadow-upper-bound");
            assert_eq!(value["decision"], "pass-through");
        }
    }

    #[test]
    fn classification_heuristics() {
        assert_eq!(
            classify(&observation(&["/tc/rustc", "--crate-name", "build_script_build"]).argv),
            ActionClass::BuildScriptCompile
        );
        assert_eq!(
            classify(
                &observation(&[
                    "/tc/rustc",
                    "--crate-name",
                    "serde",
                    "/home/u/.cargo/registry/src/index/serde-1.0/src/lib.rs",
                ])
                .argv
            ),
            ActionClass::RustcDependencyCompile
        );
        assert_eq!(
            classify(&observation(&["/tc/rustc", "--crate-name", "fx", "src/main.rs"]).argv),
            ActionClass::RustcWorkspaceCompile
        );
    }

    #[test]
    fn report_aggregates_per_class_from_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let mut plane = ShadowPlane::open(dir.path()).unwrap();
        let invocation = observation(&["/tc/rustc", "--crate-name", "fx"]);
        plane.on_consult("t1", &invocation, |_| "leader").unwrap();
        plane.on_consult("t2", &invocation, |_| "leader").unwrap();
        let report = shadow_report(dir.path()).unwrap();
        assert!(report.contains("\"total_consults\":2"), "{report}");
        assert!(
            report.contains(
                "\"class\":\"RustcWorkspaceCompile\",\"consults\":2,\"hit_upper_bound\":1"
            ),
            "{report}"
        );
    }

    #[test]
    fn secrets_cannot_reach_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let mut plane = ShadowPlane::open(dir.path()).unwrap();
        let invocation = ConsultObservation {
            argv: vec![
                "/tc/rustc".to_string(),
                "--cfg=API_TOKEN=\"hunter2-super-secret\"".to_string(),
            ],
            cwd: "/work".to_string(),
            env_names: vec![],
        };
        plane.on_consult("t1", &invocation, |_| "leader").unwrap();
        let receipts = std::fs::read_to_string(dir.path().join("shadow-receipts.ndjson")).unwrap();
        // argv0 is recorded; argv payload beyond argv0 stays OUT of the
        // receipt entirely (only the key digest carries it).
        assert!(!receipts.contains("hunter2"), "{receipts}");
    }

    #[test]
    fn hostile_argv0_does_not_tear_the_receipt() {
        // A tool path carrying JSON-breaking bytes must NOT produce a
        // malformed receipt (INV-4): argv0 is JSON-escaped.
        let dir = tempfile::tempdir().unwrap();
        let mut plane = ShadowPlane::open(dir.path()).unwrap();
        let invocation = ConsultObservation {
            argv: vec![
                "/weird/rustc\"with\\quote\tand\ttab\n".to_string(),
                "--crate-name".to_string(),
                "fx".to_string(),
            ],
            cwd: "/work".to_string(),
            env_names: vec![],
        };
        plane.on_consult("t1", &invocation, |_| "leader").unwrap();
        let receipts = std::fs::read_to_string(dir.path().join("shadow-receipts.ndjson")).unwrap();
        assert_eq!(receipts.lines().count(), 1, "no torn/multi-line receipt");
        // The single line parses as valid JSON and round-trips argv0.
        let value: serde_json::Value = serde_json::from_str(receipts.trim()).unwrap();
        assert_eq!(value["argv0"], "/weird/rustc\"with\\quote\tand\ttab\n");
    }
}
