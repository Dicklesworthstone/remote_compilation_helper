//! Build-script directive capture (bead E015; plan §73; risk R15).
//!
//! A build script speaks to Cargo through `cargo:` lines on stdout.
//! Those lines are SEMANTIC OUTPUT: `rustc-cfg`/`rustc-link-lib`/…
//! reshape downstream compiles, and `rerun-if-changed`/
//! `rerun-if-env-changed` declare the script's own input closure. This
//! parser captures every directive into structured evidence that:
//!
//! - **round-trips byte-exact** — the original line is retained beside
//!   the parse, so replay validation can compare the exact bytes the
//!   script emitted (a re-serialization "close enough" is not
//!   evidence);
//! - feeds keys: `rerun-if-changed` paths and `rerun-if-env-changed`
//!   variables JOIN the observed closure (E010 positive/negative sets
//!   and the F006 environment respectively);
//! - is total: unknown `cargo:` keys are captured as
//!   [`Directive::Metadata`] (the `cargo:KEY=VALUE` form Cargo passes
//!   to dependents — semantic by definition), and non-directive stdout
//!   is preserved as transcript, never dropped.
//!
//! Both `cargo:` and the newer `cargo::` prefix are accepted, and the
//! spelling is part of the byte-exact record.

/// One parsed directive (the raw line rides alongside every variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `cargo:rerun-if-changed=PATH` — joins the observed closure.
    RerunIfChanged {
        /// The path, exactly as emitted.
        path: String,
    },
    /// `cargo:rerun-if-env-changed=VAR` — joins the env closure.
    RerunIfEnvChanged {
        /// The variable name.
        var: String,
    },
    /// `cargo:rustc-<kind>=VALUE` — reshapes downstream compiles.
    Rustc {
        /// The rustc directive kind (`cfg`, `link-lib`, `link-search`,
        /// `link-arg`, `env`, `flags`, …).
        kind: String,
        /// The value, exactly as emitted.
        value: String,
    },
    /// `cargo:warning=TEXT` — presentation, not semantics.
    Warning {
        /// The warning text.
        text: String,
    },
    /// `cargo:KEY=VALUE` metadata passed to dependent build scripts —
    /// semantic (dependents read it).
    Metadata {
        /// The key.
        key: String,
        /// The value.
        value: String,
    },
}

/// One captured stdout line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedLine {
    /// The ORIGINAL line bytes (byte-exact round-trip anchor).
    pub raw: String,
    /// The parse, when the line was a directive.
    pub directive: Option<Directive>,
}

/// The captured directive evidence for one build-script run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildScriptCapture {
    /// Every stdout line in order.
    pub lines: Vec<CapturedLine>,
}

impl BuildScriptCapture {
    /// Byte-exact reconstruction of the original stdout.
    #[must_use]
    pub fn reconstruct(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(&line.raw);
            out.push('\n');
        }
        out
    }

    /// The rerun-if-changed paths (join the observed input closure).
    pub fn rerun_paths(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::RerunIfChanged { path }) => Some(path.as_str()),
            _ => None,
        })
    }

    /// The rerun-if-env-changed variables (join the env closure).
    pub fn rerun_env_vars(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::RerunIfEnvChanged { var }) => Some(var.as_str()),
            _ => None,
        })
    }

    /// The semantic directives (everything except warnings) — the
    /// key-feeding subset.
    pub fn semantic_directives(&self) -> impl Iterator<Item = &Directive> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::Warning { .. }) | None => None,
            Some(d) => Some(d),
        })
    }
}

/// Parse one line's directive, if any (`cargo:` and `cargo::` forms).
fn parse_line(line: &str) -> Option<Directive> {
    let rest = line
        .strip_prefix("cargo::")
        .or_else(|| line.strip_prefix("cargo:"))?;
    let (key, value) = rest.split_once('=')?;
    Some(match key {
        "rerun-if-changed" => Directive::RerunIfChanged {
            path: value.to_owned(),
        },
        "rerun-if-env-changed" => Directive::RerunIfEnvChanged {
            var: value.to_owned(),
        },
        "warning" => Directive::Warning {
            text: value.to_owned(),
        },
        _ => {
            if let Some(kind) = key.strip_prefix("rustc-") {
                Directive::Rustc {
                    kind: kind.to_owned(),
                    value: value.to_owned(),
                }
            } else {
                Directive::Metadata {
                    key: key.to_owned(),
                    value: value.to_owned(),
                }
            }
        }
    })
}

/// Capture a build script's stdout.
#[must_use]
pub fn capture_stdout(stdout: &str) -> BuildScriptCapture {
    BuildScriptCapture {
        lines: stdout
            .lines()
            .map(|line| CapturedLine {
                raw: line.to_owned(),
                directive: parse_line(line),
            })
            .collect(),
    }
}

/// Extend a live dependency's environment from its captured Cargo run record.
///
/// Call only after binding this record to the plan's generated-input tree, and
/// pass the SAME record to `live_dependency_key`. The record is input evidence,
/// not an instruction to overwrite the request: every declared value must
/// already be present in Cargo's request. Undeclared ambient variables remain
/// absent, and descriptor authority and loader injection are never promoted.
/// Both execution and the environment key receive the same additional values.
/// Validation finishes before either environment is modified.
///
/// # Errors
/// A typed live-class refusal for missing, stale, ambiguous or unmodeled
/// evidence. Callers execute normally rather than caching a different compile.
pub fn bind_rustc_environment(
    plan: &mut crate::live_dependency::DependencyActionPlan,
    record: Option<&[u8]>,
    requested: &[(String, String)],
) -> Result<(), crate::live_dependency::LiveRefusal> {
    use crate::environment::client_coordination_disposition;
    use crate::live_dependency::LiveRefusal;
    use std::collections::BTreeMap;

    let record = match (plan.generated_root.as_ref(), record) {
        (None, None) => return Ok(()),
        (Some(_), Some(record)) if record.len() <= 1024 * 1024 => record,
        _ => {
            return Err(LiveRefusal::Facts(
                "missing or invalid Cargo run record".into(),
            ));
        }
    };
    let text = std::str::from_utf8(record)
        .map_err(|_| LiveRefusal::Facts("non-UTF-8 Cargo run record".into()))?;
    if requested.len() > 4096 {
        return Err(LiveRefusal::Facts(
            "compiler environment exceeds class bound".into(),
        ));
    }
    let mut presented = BTreeMap::new();
    for (name, value) in requested {
        if presented.insert(name.as_str(), value.as_str()).is_some() {
            return Err(LiveRefusal::DuplicateEnv(name.clone()));
        }
    }
    let mut additions = BTreeMap::new();
    for line in text.lines() {
        let Some(Directive::Rustc { kind, value }) = parse_line(line.trim()) else {
            continue;
        };
        if kind != "env" {
            continue;
        }
        let (name, value) = value
            .split_once('=')
            .ok_or_else(|| LiveRefusal::Facts("malformed rustc-env directive".into()))?;
        let valid_name = !name.is_empty()
            && name.len() <= 128
            && name.bytes().enumerate().all(|(at, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (at != 0 && byte.is_ascii_digit())
            });
        let protocol_name = ["RABS", "RCH"]
            .iter()
            .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}_")));
        let loader_name = (name.starts_with("LD_") && name != "LD_LIBRARY_PATH")
            || name.starts_with("DYLD_")
            || name.starts_with("_RLD");
        if !valid_name
            || value.contains('\0')
            || protocol_name
            || loader_name
            || name == "CARGO_PRIMARY_PACKAGE"
            || client_coordination_disposition(name.as_bytes()).is_some()
            || presented.get(name).copied() != Some(value)
        {
            // Never put values (which may contain private build metadata) in
            // a refusal or diagnostic. The environment digest binds them.
            return Err(LiveRefusal::RefusedEnv(name.to_owned()));
        }
        if let Some((_, keyed)) = plan.keyed_env.iter().find(|(key, _)| key == name) {
            if keyed != value
                || !plan
                    .execution_env
                    .iter()
                    .any(|(key, v)| key == name && v == value)
            {
                return Err(LiveRefusal::RefusedEnv(name.to_owned()));
            }
            continue;
        }
        if plan.execution_env.iter().any(|(key, _)| key == name) {
            return Err(LiveRefusal::RefusedEnv(name.to_owned()));
        }
        if additions
            .insert(name.to_owned(), value.to_owned())
            .is_some_and(|previous| previous != value)
        {
            return Err(LiveRefusal::RefusedEnv(name.to_owned()));
        }
    }
    if plan.execution_env.len().saturating_add(additions.len()) > 4096 {
        return Err(LiveRefusal::Facts(
            "compiler environment exceeds class bound".into(),
        ));
    }
    for (name, value) in additions {
        plan.keyed_env.push((name.clone(), value.clone()));
        plan.execution_env.push((name, value));
    }
    plan.keyed_env.sort();
    plan.execution_env.sort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDOUT: &str = "\
cargo:rerun-if-changed=build/wrapper.h
cargo:rerun-if-env-changed=OPENSSL_DIR
cargo:rustc-cfg=has_avx2
cargo:rustc-link-lib=static=z
cargo:rustc-link-search=native=/__rabs/build/zlib-1/out
cargo:rustc-env=BUILD_PROFILE=release
cargo::rustc-check-cfg=cfg(has_avx2)
cargo:root=/__rabs/build/openssl-1/out
cargo:warning=using vendored openssl
plain non-directive output line
";

    #[test]
    fn directive_fixtures_round_trip_byte_exact() {
        // THE acceptance: reconstruct() equals the original bytes.
        let capture = capture_stdout(STDOUT);
        assert_eq!(capture.reconstruct(), STDOUT);
    }

    #[test]
    fn rerun_if_inputs_join_the_observed_closure() {
        let capture = capture_stdout(STDOUT);
        assert_eq!(
            capture.rerun_paths().collect::<Vec<_>>(),
            ["build/wrapper.h"]
        );
        assert_eq!(
            capture.rerun_env_vars().collect::<Vec<_>>(),
            ["OPENSSL_DIR"]
        );
    }

    #[test]
    fn rustc_metadata_and_warning_directives_classify() {
        let capture = capture_stdout(STDOUT);
        let semantic: Vec<&Directive> = capture.semantic_directives().collect();
        // rerun x2 + rustc x5 + metadata root=1 — warning excluded.
        assert_eq!(semantic.len(), 8);
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Rustc { kind, value }
                if kind == "link-lib" && value == "static=z"
        )));
        // Both prefixes parse; the raw spelling is retained.
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Rustc { kind, .. } if kind == "check-cfg"
        )));
        // Unknown key -> Metadata (dependents read it: semantic).
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Metadata { key, .. } if key == "root"
        )));
        // Warning parsed but NOT semantic.
        let all_warnings: Vec<_> = capture
            .lines
            .iter()
            .filter(|l| matches!(l.directive, Some(Directive::Warning { .. })))
            .collect();
        assert_eq!(all_warnings.len(), 1);
    }

    #[test]
    fn non_directive_output_is_preserved_not_dropped() {
        let capture = capture_stdout(STDOUT);
        let plain: Vec<_> = capture
            .lines
            .iter()
            .filter(|l| l.directive.is_none())
            .collect();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].raw, "plain non-directive output line");
    }
}

#[cfg(test)]
mod environment_binding_tests {
    use super::*;
    use crate::action_key::compute_action_key;
    use crate::live_dependency::{
        DependencyActionPlan, LiveDependencyKey, LiveRustcRequest, ToolchainFacts,
        live_dependency_key, plan_dependency_action,
    };
    use crate::typed_digest::compute;
    use rabs_protocol::input_evidence::{
        ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const PACKAGE: &str = "/home/test/.cargo/registry/src/index/demo-1.0.0";

    fn fixture(extra: &[(&str, &str)]) -> (DependencyActionPlan, Vec<(String, String)>) {
        let args = [
            "/toolchain/bin/rustc",
            "--crate-name=demo",
            "--crate-type=lib",
            "--emit=metadata,dep-info",
            "--out-dir=/work/target/deps",
            "--cap-lints=allow",
            "--error-format=json",
        ];
        let mut argv: Vec<String> = args.into_iter().map(str::to_owned).collect();
        argv.push(format!("{PACKAGE}/lib.rs"));
        let mut env: Vec<(String, String)> = [
            ("HOME", "/home/test"),
            ("CARGO_MANIFEST_DIR", PACKAGE),
            ("CARGO_PKG_NAME", "demo"),
            ("OUT_DIR", "/work/build/demo/out"),
            ("CARGO_MAKEFLAGS", "-j --jobserver-auth=3,4"),
        ]
        .into_iter()
        .map(|(n, v)| (n.into(), v.into()))
        .collect();
        env.extend(extra.iter().map(|(n, v)| ((*n).into(), (*v).into())));
        let plan = plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
        )
        .unwrap();
        (plan, env)
    }

    fn key(
        plan: &DependencyActionPlan,
        record: &[u8],
    ) -> Result<LiveDependencyKey, crate::live_dependency::LiveRefusal> {
        let toolchain = ToolchainFacts {
            compiler_binary_digest: compute("rabs.tool-binary.v1", b"compiler"),
            verbose_version: "rustc fixture\nhost: x86_64-unknown-linux-gnu\nLLVM version: fixture"
                .into(),
            sysroot_root_digest: compute("rabs.live-dependency.sysroot-tree.v1", b"sysroot"),
            runtime_libraries: Vec::new(),
        };
        let inputs = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: vec![PositiveInput {
                virtual_path: RawBytes::new(plan.input_virtual_path("lib.rs").into_bytes()),
                object: ObjectId(compute("rabs.test-input.v1", b"source")),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            }],
            ..ActionInputManifest::default()
        };
        live_dependency_key(plan, &toolchain, &[], &[], Some(record), &inputs)
    }

    #[test]
    fn declared_values_reach_execution_and_keys_but_ambient_values_stay_absent() {
        let record = b"cargo:rustc-env=BUILD_LABEL=left side=right\ncargo::rustc-env=EMPTY=\n";
        let (mut plan, env) = fixture(&[
            ("BUILD_LABEL", "left side=right"),
            ("EMPTY", ""),
            ("UNDECLARED", "private"),
        ]);
        assert!(
            key(&plan, record).is_err(),
            "baseline refuses a scrubbed rustc-env"
        );
        bind_rustc_environment(&mut plan, Some(record), &env).unwrap();
        for pair in [
            ("BUILD_LABEL".into(), "left side=right".into()),
            ("EMPTY".into(), "".into()),
        ] {
            assert!(plan.execution_env.contains(&pair));
            assert!(plan.keyed_env.contains(&pair));
        }
        assert!(!plan.execution_env.iter().any(|(n, _)| n == "UNDECLARED"));
        assert!(!plan.keyed_env.iter().any(|(n, _)| n == "CARGO_MAKEFLAGS"));
        assert!(
            plan.execution_env
                .iter()
                .any(|(n, _)| n == "CARGO_MAKEFLAGS")
        );
        let current = key(&plan, record).unwrap();
        assert_eq!(
            current.action_key,
            compute_action_key(&current.descriptor).final_key
        );
        let again = plan.clone();
        bind_rustc_environment(&mut plan, Some(record), &env).unwrap();
        assert_eq!(plan, again, "idempotent binding cannot duplicate a name");
    }

    #[test]
    fn changed_declared_value_changes_the_environment_and_final_action_key() {
        let mut results = Vec::new();
        for value in ["first", "second"] {
            let (mut plan, env) = fixture(&[("BUILD_LABEL", value)]);
            let record = format!("cargo::rustc-env=BUILD_LABEL={value}\n");
            bind_rustc_environment(&mut plan, Some(record.as_bytes()), &env).unwrap();
            results.push(key(&plan, record.as_bytes()).unwrap());
        }
        assert_ne!(
            results[0].descriptor.environment,
            results[1].descriptor.environment
        );
        assert_ne!(results[0].action_key, results[1].action_key);
    }

    #[test]
    fn stale_missing_or_ambiguous_values_never_partially_change_the_plan() {
        for record in [
            "cargo::rustc-env=GOOD=ok\ncargo::rustc-env=MISSING=bad\n",
            "cargo::rustc-env=GOOD=stale\n",
            "cargo::rustc-env=GOOD=ok\ncargo::rustc-env=GOOD=different\n",
            "cargo::rustc-env=GOOD=ok\ncargo::rustc-env=malformed\n",
            "cargo::rustc-env=GOOD=ok\ncargo::rustc-env=BAD-NAME=x\n",
            "cargo::rustc-env=GOOD=ok\ncargo::rustc-env=HOME=/elsewhere\n",
        ] {
            let (mut plan, env) = fixture(&[("GOOD", "ok"), ("BAD-NAME", "x")]);
            let before = plan.clone();
            assert!(bind_rustc_environment(&mut plan, Some(record.as_bytes()), &env).is_err());
            assert_eq!(plan, before, "{record}");
        }
        let (mut plan, mut env) = fixture(&[("GOOD", "ok")]);
        let before = plan.clone();
        env.push(("GOOD".into(), "ok".into()));
        assert!(
            bind_rustc_environment(&mut plan, Some(b"cargo::rustc-env=GOOD=ok\n"), &env).is_err()
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn build_scripts_cannot_promote_loader_or_coordination_authority() {
        for name in [
            "MAKEFLAGS",
            "MFLAGS",
            "CARGO_MAKEFLAGS",
            "NUM_JOBS",
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_TRACE_LOADED_OBJECTS",
            "DYLD_INSERT_LIBRARIES",
            "_RLD_LIST",
            "RABS_CAPTURE_WAIT_MS",
            "RCH_SOCKET_PATH",
            "CARGO_PRIMARY_PACKAGE",
        ] {
            let (mut plan, mut env) = fixture(&[]);
            let before = plan.clone();
            env.retain(|(key, _)| key != name);
            env.push((name.into(), "value".into()));
            let record = format!("cargo::rustc-env={name}=value\n");
            assert!(
                bind_rustc_environment(&mut plan, Some(record.as_bytes()), &env).is_err(),
                "{name}"
            );
            assert_eq!(plan, before);
        }
    }

    #[test]
    fn run_record_and_environment_bounds_are_fail_closed() {
        let (plan, env) = fixture(&[]);
        let oversized_record = vec![b'x'; 1024 * 1024 + 1];
        for record in [
            None,
            Some(b"\xff".as_slice()),
            Some(oversized_record.as_slice()),
        ] {
            let mut changed = plan.clone();
            assert!(bind_rustc_environment(&mut changed, record, &env).is_err());
            assert_eq!(changed, plan);
        }
        let mut unbound = plan.clone();
        unbound.generated_root = None;
        assert!(bind_rustc_environment(&mut unbound, Some(b""), &env).is_err());
        assert!(bind_rustc_environment(&mut unbound, None, &env).is_ok());
        let mut oversized = env.clone();
        oversized.extend((0..4097).map(|i| (format!("X_{i}"), "v".into())));
        let mut changed = plan.clone();
        assert!(bind_rustc_environment(&mut changed, Some(b""), &oversized).is_err());
        assert_eq!(changed, plan);
    }

    #[test]
    fn equal_duplicates_and_existing_keyed_values_are_preserved_without_inheritance() {
        let record = b"cargo::rustc-env=BUILD_LABEL=ok\ncargo:rustc-env=BUILD_LABEL=ok\ncargo::rustc-env=HOME=/home/test\n";
        let (mut plan, env) = fixture(&[("BUILD_LABEL", "ok")]);
        bind_rustc_environment(&mut plan, Some(record), &env).unwrap();
        assert_eq!(
            plan.execution_env
                .iter()
                .filter(|(n, _)| n == "BUILD_LABEL")
                .count(),
            1
        );
        assert_eq!(
            plan.keyed_env.iter().filter(|(n, _)| n == "HOME").count(),
            1
        );
        assert!(key(&plan, record).is_ok());
    }
}
