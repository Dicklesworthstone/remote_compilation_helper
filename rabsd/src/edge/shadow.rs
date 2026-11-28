//! The shadow decision plane (bead S4 / bridge plan Phase S) — M0's
//! "shadow-only" promise, delivered: every wrapper consult computes a
//! key through the REAL Epic F pipeline (`rabs_key::action_key::
//! compute_action_key` — the same twelve-slot canonical encoding
//! production will use), records a decision receipt, and answers
//! pass-through. Nothing is served; everything is learned.
//!
//! ## Shadow-grade honesty
//!
//! Shadow consults extract all twelve [`ActionDescriptor`] slots from the
//! observed compiler invocation, toolchain stat metadata, working directory,
//! and environment-variable names (via `rabs_key::invocation::parse`) so
//! shadow-mode key diffs and fragmentation diagnostics reflect real flags,
//! `--extern` dependencies, `--emit`/`--crate-type` outputs, `--target`
//! platforms, `-C`/`-Z` execution semantics, `--remap-path-prefix` path
//! policy, and `--cfg` conditions. Because shadow pass-through does not hash
//! transitive source or dependency file contents, `projection_epoch` stays `0`
//! and every receipt declares `grade: shadow-upper-bound`: two invocations
//! with identical arguments but modified file contents still shadow-collide,
//! so the reported hit count remains an honest upper bound.

use rabs_key::action_key::compute_action_key;
use rabs_key::invocation::{SourceInput, parse as parse_rustc_invocation};
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
    let crate_name = argv.iter().enumerate().find_map(|(idx, arg)| {
        arg.strip_prefix("--crate-name=").or_else(|| {
            (arg == "--crate-name")
                .then(|| argv.get(idx + 1).map(String::as_str))
                .flatten()
        })
    });
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

fn format_kv_list(items: &[(String, Option<String>)]) -> String {
    items
        .iter()
        .map(|(k, v)| match v {
            Some(val) => format!("{k}={val}"),
            None => k.clone(),
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

fn extract_flag_values(argv: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < argv.len() {
        if let Some(val) = argv[i].strip_prefix(&prefix) {
            out.push(val.to_owned());
        } else if argv[i] == flag
            && let Some(next) = argv.get(i + 1)
        {
            out.push(next.clone());
            i += 1;
        }
        i += 1;
    }
    out
}

fn extract_short_flag_values(argv: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == flag {
            if let Some(next) = argv.get(i + 1) {
                out.push(next.clone());
                i += 1;
            }
        } else if !argv[i].starts_with("--")
            && let Some(rest) = argv[i].strip_prefix(flag)
        {
            out.push(rest.to_owned());
        }
        i += 1;
    }
    out
}

/// Build the shadow-grade descriptor from an observation. All twelve slots are
/// derived from the real observed invocation, toolchain stat metadata, working
/// directory, and environment-variable names (never hardcoded placeholders),
/// while `projection_epoch = 0` keeps the shadow upper-bound contract explicit.
#[must_use]
pub fn shadow_descriptor(observation: &ConsultObservation) -> ActionDescriptor {
    let argv_joined = observation.argv.join("\u{1f}");
    let parsed = parse_rustc_invocation(&observation.argv, None).ok();
    let compiler_tool = parsed
        .as_ref()
        .map(|inv| inv.compiler_argv0.as_str())
        .or_else(|| observation.argv.first().map(String::as_str));
    let toolchain_identity =
        compiler_tool.map_or_else(String::new, |tool| match std::fs::metadata(tool) {
            Ok(meta) => format!("{tool}|len={}|mtime={:?}", meta.len(), meta.modified().ok()),
            Err(_) => format!("{tool}|unstat"),
        });

    let mut env_names: Vec<&str> = observation.env_names.iter().map(String::as_str).collect();
    env_names.sort_unstable();
    env_names.dedup();

    let (
        normalized_invocation_bytes,
        action_inputs_payload,
        negative_deps_payload,
        dependency_inputs_payload,
        output_platform_payload,
        sandbox_policy_payload,
        path_policy_payload,
        exec_semantics_payload,
        output_decls_payload,
    ) = if let Some(inv) = &parsed {
        let source_desc = match &inv.source {
            Some(SourceInput::Path(path)) => format!("path:{path}"),
            Some(SourceInput::Stdin(digest)) => format!("stdin:{}", hex(&digest.bytes)),
            None => "none".to_owned(),
        };
        let extra_filename = inv
            .codegen
            .iter()
            .filter(|(k, _)| k == "extra-filename" || k == "metadata")
            .map(|(k, v)| format!("{k}={}", v.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join(",");
        let action_inputs = format!(
            "shadow-declared|source={source_desc}|crate={}|edition={}|id={extra_filename}",
            inv.crate_name.as_deref().unwrap_or(""),
            inv.edition.as_deref().unwrap_or(""),
        );

        let mut cfgs = inv.cfgs.clone();
        cfgs.sort();
        let mut features = inv.features.clone();
        features.sort();
        let mut check_cfgs = extract_flag_values(&inv.passthrough, "--check-cfg");
        check_cfgs.sort();
        let negative_deps = format!(
            "cfgs={}|features={}|check_cfg={}",
            cfgs.join("\u{1f}"),
            features.join("\u{1f}"),
            check_cfgs.join("\u{1f}"),
        );

        let mut externs = inv.externs.clone();
        externs.sort();
        let dependency_inputs = format!(
            "externs={}|lib_search={}|native_libs={}",
            format_kv_list(&externs),
            inv.lib_search.join("\u{1f}"),
            inv.native_libs.join("\u{1f}"),
        );

        let output_platform = inv
            .target
            .clone()
            .unwrap_or_else(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS));

        let has_wrapper_env = env_names.iter().any(|name| {
            name.starts_with("RUSTC_WRAPPER")
                || name.starts_with("RUSTC_WORKSPACE_WRAPPER")
                || *name == "CARGO_BUILD_RUSTC_WRAPPER"
                || name.starts_with("CARGO_RABS_")
        });
        let sandbox_policy = format!(
            "mode=shadow-pass-through|wrappers={}|wrapper_env={has_wrapper_env}",
            inv.wrapper_chain.join(",")
        );

        let remaps = extract_flag_values(&inv.passthrough, "--remap-path-prefix");
        let path_unstable: Vec<String> = inv
            .unstable
            .iter()
            .filter(|(k, _)| k.contains("remap") || k.contains("trim-paths"))
            .map(|(k, v)| match v {
                Some(val) => format!("{k}={val}"),
                None => k.clone(),
            })
            .collect();
        let path_policy = format!(
            "remap={}|unstable={}",
            remaps.join("\u{1f}"),
            path_unstable.join("\u{1f}"),
        );

        let lints: Vec<String> = inv
            .lints
            .iter()
            .map(|l| format!("{}={}", l.level, l.name))
            .collect();
        let exec_semantics = format!(
            "edition={}|cap_lints={}|codegen={}|unstable={}|lints={}",
            inv.edition.as_deref().unwrap_or(""),
            inv.cap_lints.as_deref().unwrap_or(""),
            format_kv_list(&inv.codegen),
            format_kv_list(&inv.unstable),
            lints.join("\u{1f}"),
        );

        let explicit_out = extract_short_flag_values(&inv.passthrough, "-o");
        let output_decls = format!(
            "emit={}|crate_types={}|out_dir={}|output={}",
            inv.emit.join(","),
            inv.crate_types.join(","),
            inv.out_dir.as_deref().unwrap_or(""),
            explicit_out.join(","),
        );

        (
            inv.canonical_bytes(),
            action_inputs,
            negative_deps,
            dependency_inputs,
            output_platform,
            sandbox_policy,
            path_policy,
            exec_semantics,
            output_decls,
        )
    } else {
        // Unparsed / non-rustc fallback: still derive each slot from observed
        // argv flags rather than a shared hardcoded constant.
        let action_inputs = format!(
            "unparsed-argv|len={}|cwd={}",
            observation.argv.len(),
            observation.cwd
        );
        let negative_deps = format!(
            "cfgs={}|check_cfg={}",
            extract_flag_values(&observation.argv, "--cfg").join("\u{1f}"),
            extract_flag_values(&observation.argv, "--check-cfg").join("\u{1f}"),
        );
        let dependency_inputs = format!(
            "externs={}|L={}",
            extract_flag_values(&observation.argv, "--extern").join("\u{1f}"),
            extract_short_flag_values(&observation.argv, "-L").join("\u{1f}"),
        );
        let output_platform = extract_flag_values(&observation.argv, "--target")
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS));
        let sandbox_policy = "mode=shadow-pass-through|unparsed=true".to_owned();
        let path_policy = format!(
            "remap={}",
            extract_flag_values(&observation.argv, "--remap-path-prefix").join("\u{1f}")
        );
        let exec_semantics = format!(
            "C={}|Z={}",
            extract_short_flag_values(&observation.argv, "-C").join("\u{1f}"),
            extract_short_flag_values(&observation.argv, "-Z").join("\u{1f}"),
        );
        let output_decls = format!(
            "emit={}|crate_type={}|out_dir={}|o={}",
            extract_flag_values(&observation.argv, "--emit").join(","),
            extract_flag_values(&observation.argv, "--crate-type").join(","),
            extract_flag_values(&observation.argv, "--out-dir").join(","),
            extract_short_flag_values(&observation.argv, "-o").join(","),
        );
        (
            argv_joined.into_bytes(),
            action_inputs,
            negative_deps,
            dependency_inputs,
            output_platform,
            sandbox_policy,
            path_policy,
            exec_semantics,
            output_decls,
        )
    };

    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 0, // 0 = shadow projection (upper bound)
        action_class: classify(&observation.argv),
        normalized_invocation: compute(
            "rabs.shadow.normalized-invocation.v2",
            &normalized_invocation_bytes,
        ),
        virtual_working_directory: compute(
            "rabs.shadow.working-directory.v1",
            observation.cwd.as_bytes(),
        ),
        action_inputs: compute(
            "rabs.shadow.action-inputs.v2",
            action_inputs_payload.as_bytes(),
        ),
        negative_dependencies: compute(
            "rabs.shadow.negative-deps.v2",
            negative_deps_payload.as_bytes(),
        ),
        dependency_inputs: compute(
            "rabs.shadow.dependency-inputs.v2",
            dependency_inputs_payload.as_bytes(),
        ),
        toolchain: compute("rabs.shadow.toolchain.v1", toolchain_identity.as_bytes()),
        output_platform: compute(
            "rabs.shadow.output-platform.v2",
            output_platform_payload.as_bytes(),
        ),
        environment: compute(
            "rabs.shadow.environment-names.v2",
            env_names.join("\u{1f}").as_bytes(),
        ),
        sandbox_semantic_policy: compute(
            "rabs.shadow.sandbox-policy.v2",
            sandbox_policy_payload.as_bytes(),
        ),
        build_path_semantic_policy: compute(
            "rabs.shadow.path-policy.v2",
            path_policy_payload.as_bytes(),
        ),
        execution_semantics: compute(
            "rabs.shadow.exec-semantics.v2",
            exec_semantics_payload.as_bytes(),
        ),
        output_declarations: compute(
            "rabs.shadow.output-decls.v2",
            output_decls_payload.as_bytes(),
        ),
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

    #[test]
    fn shadow_descriptor_extracts_real_per_slot_components_without_placeholders() {
        let base = ConsultObservation {
            argv: vec![
                "/tc/rustc".into(),
                "--crate-name".into(),
                "demo".into(),
                "--crate-type".into(),
                "lib".into(),
                "--edition=2024".into(),
                "--emit=dep-info,metadata".into(),
                "--out-dir".into(),
                "/work/target/debug/deps".into(),
                "--extern".into(),
                "serde=/work/target/debug/deps/libserde-1.rmeta".into(),
                "--cfg".into(),
                "feature=\"std\"".into(),
                "--remap-path-prefix=/work=/rabs/src".into(),
                "-C".into(),
                "opt-level=0".into(),
                "--target".into(),
                "x86_64-unknown-linux-gnu".into(),
                "src/lib.rs".into(),
            ],
            cwd: "/work".into(),
            env_names: vec!["CARGO_PKG_NAME".into(), "CARGO_HOME".into()],
        };
        let d_base = shadow_descriptor(&base);

        // Reordered env_names produce identical environment slot.
        let mut reordered_env = base.clone();
        reordered_env.env_names.reverse();
        assert_eq!(
            d_base.environment,
            shadow_descriptor(&reordered_env).environment
        );

        // Volatile presentation flags (--color) do not fragment shadow keys.
        let mut color_always = base.clone();
        color_always.argv.push("--color=always".into());
        let mut color_never = base.clone();
        color_never.argv.push("--color=never".into());
        assert_eq!(
            shadow_descriptor(&color_always),
            shadow_descriptor(&color_never)
        );

        // Equals-form --crate-name=build_script_build classifies truthfully.
        assert_eq!(
            classify(&observation(&["/tc/rustc", "--crate-name=build_script_build"]).argv),
            ActionClass::BuildScriptCompile
        );

        // Attached -o form mutates output_declarations and preserves exact filename (e.g. -o=foo != -ofoo).
        let mut explicit_out = base.clone();
        explicit_out.argv.push("-o/tmp/out.rlib".into());
        assert_ne!(
            d_base.output_declarations,
            shadow_descriptor(&explicit_out).output_declarations
        );
        let mut eq_out = base.clone();
        eq_out.argv.push("-o=foo".into());
        let mut plain_out = base.clone();
        plain_out.argv.push("-ofoo".into());
        assert_ne!(
            shadow_descriptor(&eq_out).output_declarations,
            shadow_descriptor(&plain_out).output_declarations
        );

        // Wrapper env vars (including RUSTC_WORKSPACE_WRAPPER) mutate sandbox_semantic_policy.
        let mut with_ws_wrapper = base.clone();
        with_ws_wrapper
            .env_names
            .push("RUSTC_WORKSPACE_WRAPPER".into());
        assert_ne!(
            d_base.sandbox_semantic_policy,
            shadow_descriptor(&with_ws_wrapper).sandbox_semantic_policy
        );

        // Changing --extern mutates dependency_inputs without touching output_declarations.
        let mut diff_extern = base.clone();
        diff_extern.argv[10] = "serde=/work/target/debug/deps/libserde-2.rmeta".into();
        let d_extern = shadow_descriptor(&diff_extern);
        assert_ne!(d_base.dependency_inputs, d_extern.dependency_inputs);
        assert_eq!(d_base.output_declarations, d_extern.output_declarations);

        // Changing --emit mutates output_declarations without touching execution_semantics.
        let mut diff_emit = base.clone();
        diff_emit.argv[6] = "--emit=dep-info,link".into();
        let d_emit = shadow_descriptor(&diff_emit);
        assert_ne!(d_base.output_declarations, d_emit.output_declarations);
        assert_eq!(d_base.execution_semantics, d_emit.execution_semantics);

        // Changing -C opt-level mutates execution_semantics without touching dependency_inputs.
        let mut diff_opt = base.clone();
        diff_opt.argv[15] = "opt-level=3".into();
        let d_opt = shadow_descriptor(&diff_opt);
        assert_ne!(d_base.execution_semantics, d_opt.execution_semantics);
        assert_eq!(d_base.dependency_inputs, d_opt.dependency_inputs);

        // Changing --remap-path-prefix mutates build_path_semantic_policy.
        let mut diff_remap = base.clone();
        diff_remap.argv[13] = "--remap-path-prefix=/other=/rabs/src".into();
        let d_remap = shadow_descriptor(&diff_remap);
        assert_ne!(
            d_base.build_path_semantic_policy,
            d_remap.build_path_semantic_policy
        );

        // Changing --cfg mutates negative_dependencies.
        let mut diff_cfg = base.clone();
        diff_cfg.argv[12] = "feature=\"alloc\"".into();
        let d_cfg = shadow_descriptor(&diff_cfg);
        assert_ne!(d_base.negative_dependencies, d_cfg.negative_dependencies);

        // Changing --target mutates output_platform.
        let mut diff_target = base.clone();
        diff_target.argv[17] = "aarch64-unknown-linux-gnu".into();
        let d_target = shadow_descriptor(&diff_target);
        assert_ne!(d_base.output_platform, d_target.output_platform);

        // Changing source path mutates action_inputs.
        let mut diff_src = base.clone();
        diff_src.argv[18] = "src/main.rs".into();
        let d_src = shadow_descriptor(&diff_src);
        assert_ne!(d_base.action_inputs, d_src.action_inputs);
    }
}
