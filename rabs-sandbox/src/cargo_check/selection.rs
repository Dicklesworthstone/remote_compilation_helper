//! One bounded Cargo compilation selection shared by planning and execution.
//!
//! These are target/feature selectors, not arbitrary Cargo arguments. The
//! driver supplies the retained manifest, offline/locked mode, compiler,
//! output directory and job budget itself. Both the nonexecuting unit-graph
//! query and the subsequent compilation use the same Cargo selection. Test
//! harness and Clippy lint arguments form separate tails after the driver's
//! Cargo options.

use serde::{Deserialize, Serialize};
use std::io;

const MAX_VALUES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;

/// The captured Cargo command, separate from package and target selectors.
///
/// `Check` and `Build` compile without running the requested targets. `Test`
/// also runs Cargo's selected tests and doctests unless `no_run` is selected;
/// test outcomes are never action-cache results. `Clippy` checks the selected
/// targets with the captured lint driver, whose results are never rustc cache
/// results. Cargo can run build scripts and load procedural macros in every
/// command. The validated unit graph
/// selects the required closed-worker boundary for compiler cache authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompilationCommand {
    #[default]
    Check,
    Build,
    Test,
    Clippy,
}

impl CompilationCommand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Build => "build",
            Self::Test => "test",
            Self::Clippy => "clippy",
        }
    }
}

/// Cargo's ordinary package, feature and target selection for a compilation.
///
/// An empty selection means Cargo's default targets and default members. The
/// driver may explicitly supply `lib: true` for a library-only check. Unknown
/// fields cannot become command options or select project execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompilationSelection {
    pub workspace: bool,
    pub packages: Vec<String>,
    pub exclude: Vec<String>,
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    pub lib: bool,
    pub bins: bool,
    pub tests: bool,
    pub examples: bool,
    pub benches: bool,
    pub all_targets: bool,
    pub bin: Vec<String>,
    pub test: Vec<String>,
    pub example: Vec<String>,
    pub bench: Vec<String>,
    pub release: bool,
    /// Built-in compilation targets in argument order. Empty retains Cargo's
    /// default; `host-tuple` is resolved by the captured Cargo. JSON target
    /// specifications are additional inputs and are not admitted as names.
    pub target: Vec<String>,
    /// Cargo's profile name, not profile settings. Cargo validates existence
    /// and inheritance in the captured workspace. The unit graph and actual
    /// compilation use the same value, including `test` and its development units.
    pub profile: Option<String>,
    /// Select documentation tests, only for the `Test` command.
    pub doc: bool,
    /// Compile Cargo's test executables without running them.
    pub no_run: bool,
    /// Let Cargo run the remaining test executables after one fails.
    pub no_fail_fast: bool,
    /// Cargo's optional positional test-name filter, passed as one argument.
    pub test_filter: Option<String>,
    /// Literal test-harness arguments. These are appended after `--`, never
    /// interpreted as Cargo configuration, source, toolchain or output options.
    pub test_args: Vec<String>,
    /// Lint only the selected packages, leaving dependency rustc compilation to
    /// Cargo. This flag belongs to Clippy rather than to ordinary Cargo check.
    pub no_deps: bool,
    /// Bounded lint-level controls after `--`, only for Clippy. Arbitrary rustc
    /// flags, response files and output/configuration paths are not admitted.
    pub lint_args: Vec<String>,
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Names can select captured compiler/workspace semantics, never an additional
/// JSON target specification or a host file. Deliberately stricter than Cargo's
/// general --target syntax until target-specification capture is modeled.
fn ordinary_name(value: &str) -> bool {
    value.len() <= MAX_VALUE_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_lint_arguments(args: &[String]) -> io::Result<()> {
    let mut at = 0;
    while at < args.len() {
        let argument = &args[at];
        let (option, value) = if let Some((option, value)) = argument.split_once('=') {
            (option, value)
        } else if ["-A", "-W", "-D", "-F"]
            .iter()
            .any(|option| argument.starts_with(*option) && argument.len() > option.len())
        {
            (&argument[..2], &argument[2..])
        } else {
            at += 1;
            let value = args
                .get(at)
                .ok_or_else(|| invalid("Clippy lint option requires a value"))?;
            (argument.as_str(), value.as_str())
        };
        if option == "--cap-lints" {
            if !matches!(value, "allow" | "warn" | "deny" | "forbid") {
                return Err(invalid("unsupported Clippy lint cap"));
            }
        } else {
            if !matches!(
                option,
                "-A" | "-W"
                    | "-D"
                    | "-F"
                    | "--allow"
                    | "--warn"
                    | "--force-warn"
                    | "--deny"
                    | "--forbid"
            ) || (argument.contains('=') && !option.starts_with("--"))
            {
                return Err(invalid("unsupported Clippy lint option"));
            }
            if value.len() > 256
                || !value.split("::").all(|part| {
                    part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'_' | b'-')
                        })
                })
            {
                return Err(invalid("invalid Clippy lint name"));
            }
        }
        at += 1;
    }
    Ok(())
}

impl CompilationSelection {
    /// Construct the complete selected compilation prefix without host authority.
    ///
    /// Cargo remains the authority for package-spec, feature and target-name
    /// syntax. Values are passed as distinct argv entries, never shell text.
    /// Leading options, control bytes and oversized requests are refused here
    /// before any source capture or command planning can start.
    pub fn cargo_arguments(&self, command: CompilationCommand) -> io::Result<Vec<String>> {
        if command != CompilationCommand::Test
            && (self.doc
                || self.no_run
                || self.no_fail_fast
                || self.test_filter.is_some()
                || !self.test_args.is_empty())
        {
            return Err(invalid("test selection requires the Cargo test command"));
        }
        if command != CompilationCommand::Clippy && (self.no_deps || !self.lint_args.is_empty()) {
            return Err(invalid(
                "Clippy selection requires the Cargo clippy command",
            ));
        }
        validate_lint_arguments(&self.lint_args)?;
        if !self.exclude.is_empty() && !self.workspace {
            return Err(invalid(
                "Cargo compilation exclusions require workspace selection",
            ));
        }
        if self.release && self.profile.is_some() {
            return Err(invalid(
                "choose release or an explicit Cargo compilation profile, not both",
            ));
        }
        if self.target.iter().any(|target| !ordinary_name(target)) {
            return Err(invalid(
                "Cargo compilation targets must be built-in names, not target-specification paths",
            ));
        }
        if self
            .profile
            .as_ref()
            .is_some_and(|profile| !ordinary_name(profile))
        {
            return Err(invalid("invalid Cargo compilation profile name"));
        }
        let values = [
            ("--package", &self.packages),
            ("--exclude", &self.exclude),
            ("--features", &self.features),
            ("--bin", &self.bin),
            ("--test", &self.test),
            ("--example", &self.example),
            ("--bench", &self.bench),
            ("--target", &self.target),
        ];
        let count = values.iter().map(|(_, values)| values.len()).sum::<usize>()
            + usize::from(self.profile.is_some())
            + usize::from(self.test_filter.is_some())
            + self.test_args.len()
            + self.lint_args.len();
        if count > MAX_VALUES {
            return Err(invalid("Cargo compilation selection has too many values"));
        }
        let mut args = vec![command.as_str().to_owned()];
        for (enabled, option) in [
            (self.workspace, "--workspace"),
            (self.all_features, "--all-features"),
            (self.no_default_features, "--no-default-features"),
            (self.lib, "--lib"),
            (self.bins, "--bins"),
            (self.tests, "--tests"),
            (self.examples, "--examples"),
            (self.benches, "--benches"),
            (self.all_targets, "--all-targets"),
            (self.release, "--release"),
            (self.doc, "--doc"),
            (self.no_run, "--no-run"),
            (self.no_fail_fast, "--no-fail-fast"),
            (self.no_deps, "--no-deps"),
        ] {
            if enabled {
                args.push(option.to_owned());
            }
        }
        for (option, values) in values {
            for value in values {
                if value.is_empty()
                    || value.len() > MAX_VALUE_BYTES
                    || value.starts_with('-')
                    || value.chars().any(char::is_control)
                {
                    return Err(invalid("invalid Cargo compilation selection value"));
                }
                args.push(option.to_owned());
                args.push(value.clone());
            }
        }
        if let Some(profile) = &self.profile {
            args.push("--profile".into());
            args.push(profile.clone());
        }
        if let Some(filter) = &self.test_filter {
            if filter.len() > MAX_VALUE_BYTES
                || filter.starts_with('-')
                || filter.chars().any(char::is_control)
            {
                return Err(invalid("invalid Cargo test-name filter"));
            }
            args.push(filter.clone());
        }
        if self
            .test_args
            .iter()
            .any(|arg| arg.len() > MAX_VALUE_BYTES || arg.chars().any(char::is_control))
        {
            return Err(invalid("invalid test-harness argument"));
        }
        let tail = if command == CompilationCommand::Clippy {
            &self.lint_args
        } else {
            &self.test_args
        };
        let runtime_bytes =
            tail.iter().map(String::len).sum::<usize>() + if tail.is_empty() { 0 } else { 2 };
        if args.iter().map(String::len).sum::<usize>() + runtime_bytes > MAX_ARGUMENT_BYTES {
            return Err(invalid(
                "Cargo compilation selection exceeds its argument byte budget",
            ));
        }
        Ok(args)
    }

    /// Construct the test-harness or Clippy lint tail after validating the entire
    /// selection, including its shared count and byte limits. Append this only
    /// after all driver-owned Cargo options. Unit-graph queries omit test-harness
    /// arguments, but retain Clippy lint arguments for the same driver invocation.
    pub fn runtime_arguments(&self, command: CompilationCommand) -> io::Result<Vec<String>> {
        self.cargo_arguments(command)?;
        let tail = if command == CompilationCommand::Clippy {
            &self.lint_args
        } else {
            &self.test_args
        };
        if tail.is_empty() {
            return Ok(Vec::new());
        }
        Ok(std::iter::once("--".to_owned())
            .chain(tail.iter().cloned())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_selection_preserves_cargos_default_member_and_target_selection() {
        assert_eq!(
            CompilationSelection::default()
                .cargo_arguments(CompilationCommand::Check)
                .unwrap(),
            ["check"]
        );
        assert_eq!(
            CompilationSelection {
                lib: true,
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Check)
            .unwrap(),
            ["check", "--lib"]
        );
        assert_eq!(
            CompilationSelection::default()
                .cargo_arguments(CompilationCommand::Build)
                .unwrap(),
            ["build"]
        );
        assert_eq!(
            CompilationSelection::default()
                .cargo_arguments(CompilationCommand::Test)
                .unwrap(),
            ["test"]
        );
    }

    #[test]
    fn package_features_and_named_targets_are_literal_cargo_arguments() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "workspace":true, "exclude":["integration-*"],
            "packages":["core@1.0.0", "app"],
            "features":["app/fast,core/serde", "core/std"],
            "no_default_features":true, "release":true,
            "bin":["server", "cli"], "test":["roundtrip"],
            "example":["client"], "bench":["throughput"]
        }))
        .unwrap();
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .unwrap(),
            [
                "check",
                "--workspace",
                "--no-default-features",
                "--release",
                "--package",
                "core@1.0.0",
                "--package",
                "app",
                "--exclude",
                "integration-*",
                "--features",
                "app/fast,core/serde",
                "--features",
                "core/std",
                "--bin",
                "server",
                "--bin",
                "cli",
                "--test",
                "roundtrip",
                "--example",
                "client",
                "--bench",
                "throughput"
            ]
        );
    }

    #[test]
    fn selections_cannot_supply_commands_environment_or_output_authority() {
        for (field, value) in [
            ("args", json!(["build", "--config=bad"])),
            ("command", json!("run")),
            ("env", json!({"RUSTC_WRAPPER":"/bad"})),
            ("manifest_path", json!("/other/Cargo.toml")),
            ("target_dir", json!("/other/target")),
            ("config", json!("bad")),
            ("unstable", json!(true)),
        ] {
            let mut selection = json!({});
            selection[field] = value;
            assert!(
                serde_json::from_value::<CompilationSelection>(selection).is_err(),
                "{field}"
            );
        }
        for value in [
            "",
            "--config=bad",
            "-Zunstable-options",
            "feature\0",
            "name\n",
        ] {
            let selection = CompilationSelection {
                features: vec![value.into()],
                ..CompilationSelection::default()
            };
            for command in [CompilationCommand::Check, CompilationCommand::Build] {
                assert!(
                    selection.cargo_arguments(command).is_err(),
                    "{command:?}: {value:?}"
                );
            }
        }
    }

    #[test]
    fn argument_limits_apply_to_the_whole_selection_and_exclusions_require_workspace() {
        let mut selection = CompilationSelection {
            features: vec!["feature".into(); MAX_VALUES],
            ..CompilationSelection::default()
        };
        assert!(selection.cargo_arguments(CompilationCommand::Check).is_ok());
        selection.packages.push("package".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.packages.clear();
        selection.features = vec!["a".repeat(MAX_VALUE_BYTES); MAX_VALUES];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.features = vec!["a".repeat(MAX_VALUE_BYTES + 1)];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.features.clear();
        selection.exclude.push("excluded".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.workspace = true;
        assert!(selection.cargo_arguments(CompilationCommand::Check).is_ok());
    }

    #[test]
    fn compilation_targets_and_profile_survive_profile_roundtrip_in_order() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "workspace":true, "lib":true,
            "target":["wasm32-unknown-unknown", "aarch64-unknown-linux-gnu", "host-tuple"],
            "profile":"check-fast", "features":["core/serde"]
        }))
        .unwrap();
        let roundtrip: CompilationSelection =
            serde_json::from_value(serde_json::to_value(&selection).unwrap()).unwrap();
        assert_eq!(roundtrip, selection);
        assert_eq!(
            roundtrip
                .cargo_arguments(CompilationCommand::Check)
                .unwrap(),
            [
                "check",
                "--workspace",
                "--lib",
                "--features",
                "core/serde",
                "--target",
                "wasm32-unknown-unknown",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--target",
                "host-tuple",
                "--profile",
                "check-fast"
            ]
        );
    }

    #[test]
    fn target_and_profile_selectors_never_grant_external_file_authority() {
        for name in [
            "",
            "--config=bad",
            "-Zunstable-options",
            "/tmp/target.json",
            "./target.json",
            "../target",
            "target.json",
            "spec/target",
            "C:\\spec\\target.json",
            "target\0",
            "target\n",
            "host tuple",
            "target=wasm32",
            "targét",
            ".",
            "..",
        ] {
            let target = CompilationSelection {
                target: vec![name.into()],
                ..CompilationSelection::default()
            };
            let profile = CompilationSelection {
                profile: Some(name.into()),
                ..CompilationSelection::default()
            };
            for command in [CompilationCommand::Check, CompilationCommand::Build] {
                assert!(
                    target.cargo_arguments(command).is_err(),
                    "{command:?} target {name:?}"
                );
                assert!(
                    profile.cargo_arguments(command).is_err(),
                    "{command:?} profile {name:?}"
                );
            }
        }
        for value in [
            json!({"target":"wasm32-unknown-unknown"}),
            json!({"target":[true]}),
            json!({"target":null}),
            json!({"profile":["release"]}),
            json!({"profile":{"inherits":"release"}}),
        ] {
            assert!(serde_json::from_value::<CompilationSelection>(value).is_err());
        }
    }

    #[test]
    fn explicit_profiles_do_not_silently_override_release_or_the_default() {
        for name in ["dev", "release", "test", "bench", "check_fast"] {
            let mut selection = CompilationSelection {
                profile: Some(name.into()),
                ..CompilationSelection::default()
            };
            assert_eq!(
                selection
                    .cargo_arguments(CompilationCommand::Check)
                    .unwrap(),
                ["check", "--profile", name]
            );
            selection.release = true;
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Check)
                    .is_err()
            );
        }
        let default: CompilationSelection =
            serde_json::from_value(json!({"profile":null})).unwrap();
        assert_eq!(
            default.cargo_arguments(CompilationCommand::Check).unwrap(),
            ["check"]
        );
        assert_eq!(
            CompilationSelection {
                release: true,
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Check)
            .unwrap(),
            ["check", "--release"]
        );
    }

    #[test]
    fn target_and_profile_values_share_existing_global_budgets() {
        let mut selection = CompilationSelection {
            target: vec!["host-tuple".into(); MAX_VALUES],
            ..CompilationSelection::default()
        };
        assert!(selection.cargo_arguments(CompilationCommand::Check).is_ok());
        selection.profile = Some("dev".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.target.pop();
        assert!(selection.cargo_arguments(CompilationCommand::Check).is_ok());
        selection.features.push("feature".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.features.clear();
        selection.profile = None;
        selection.target = vec!["a".repeat(MAX_VALUE_BYTES); MAX_VALUES];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.target = vec!["a".repeat(MAX_VALUE_BYTES + 1)];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        selection.target.clear();
        selection.profile = Some("a".repeat(MAX_VALUE_BYTES + 1));
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
        // Neither new field can evade the aggregate byte budget by being
        // individually bounded. These 16 values fit until a profile is added.
        selection.profile = None;
        selection.features = vec!["a".repeat(1000); 16];
        assert!(selection.cargo_arguments(CompilationCommand::Check).is_ok());
        selection.profile = Some("a".repeat(1000));
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Check)
                .is_err()
        );
    }

    #[test]
    fn build_selectors_compile_targets_without_granting_runtime_commands() {
        let selection = CompilationSelection {
            workspace: true,
            tests: true,
            examples: true,
            target: vec!["host-tuple".into()],
            profile: Some("release".into()),
            ..CompilationSelection::default()
        };
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Build)
                .unwrap(),
            [
                "build",
                "--workspace",
                "--tests",
                "--examples",
                "--target",
                "host-tuple",
                "--profile",
                "release",
            ]
        );
        for (text, expected) in [
            ("check", CompilationCommand::Check),
            ("build", CompilationCommand::Build),
            ("test", CompilationCommand::Test),
            ("clippy", CompilationCommand::Clippy),
        ] {
            let command: CompilationCommand = serde_json::from_value(json!(text)).unwrap();
            assert_eq!(command, expected);
            assert_eq!(serde_json::to_value(command).unwrap(), json!(text));
        }
        for value in [
            json!("run"),
            json!("bench"),
            json!("doc"),
            json!("check --config=bad"),
            json!("Build"),
            json!(null),
            json!([]),
            json!({}),
        ] {
            assert!(serde_json::from_value::<CompilationCommand>(value).is_err());
        }
    }

    #[test]
    fn test_selection_keeps_harness_arguments_after_driver_owned_cargo_options() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "workspace":true,
            "no_run":true,
            "no_fail_fast":true,
            "test_filter":"roundtrip::exact value",
            "test_args":["--nocapture", "--test-threads=1", "--manifest-path=/not-cargo"]
        }))
        .unwrap();
        let decoded: CompilationSelection =
            serde_json::from_value(serde_json::to_value(&selection).unwrap()).unwrap();
        assert_eq!(decoded, selection);
        let mut args = selection.cargo_arguments(CompilationCommand::Test).unwrap();
        assert_eq!(
            args,
            [
                "test",
                "--workspace",
                "--no-run",
                "--no-fail-fast",
                "roundtrip::exact value"
            ]
        );
        args.extend(["--offline".into(), "--locked".into()]);
        args.extend(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .unwrap(),
        );
        assert_eq!(
            &args[5..],
            [
                "--offline",
                "--locked",
                "--",
                "--nocapture",
                "--test-threads=1",
                "--manifest-path=/not-cargo"
            ]
        );
        assert_eq!(
            CompilationSelection {
                doc: true,
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Test)
            .unwrap(),
            ["test", "--doc"]
        );
    }

    #[test]
    fn test_only_controls_cannot_change_check_or_build_semantics() {
        for value in [
            json!({"doc":true}),
            json!({"no_run":true}),
            json!({"no_fail_fast":true}),
            json!({"test_filter":""}),
            json!({"test_args":["--nocapture"]}),
        ] {
            let selection: CompilationSelection = serde_json::from_value(value).unwrap();
            for command in [CompilationCommand::Check, CompilationCommand::Build] {
                assert!(selection.cargo_arguments(command).is_err());
                assert!(selection.runtime_arguments(command).is_err());
            }
            assert!(selection.cargo_arguments(CompilationCommand::Test).is_ok());
        }
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
        ] {
            assert!(
                CompilationSelection::default()
                    .runtime_arguments(command)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn clippy_selection_preserves_lint_order_without_admitting_compiler_options() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "workspace":true, "all_targets":true, "no_deps":true,
            "lint_args":["-D", "warnings", "-Aclippy::needless_return", "--force-warn=dead_code",
                "--cap-lints", "forbid"]
        }))
        .unwrap();
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .unwrap(),
            ["clippy", "--workspace", "--all-targets", "--no-deps"]
        );
        assert_eq!(
            selection
                .runtime_arguments(CompilationCommand::Clippy)
                .unwrap(),
            [
                "--",
                "-D",
                "warnings",
                "-Aclippy::needless_return",
                "--force-warn=dead_code",
                "--cap-lints",
                "forbid"
            ]
        );
        let decoded: CompilationSelection =
            serde_json::from_value(serde_json::to_value(&selection).unwrap()).unwrap();
        assert_eq!(decoded, selection);
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
        ] {
            assert!(selection.cargo_arguments(command).is_err());
        }
        for args in [
            vec!["--emit=link"],
            vec!["--cfg", "custom"],
            vec!["@response"],
            vec!["--sysroot", "/other"],
            vec!["-D"],
            vec!["-D", ""],
            vec!["-Dwarnings=allow"],
            vec!["-D", "warnings\n"],
            vec!["--allow", "clippy::"],
            vec!["--allow", "clippy::BAD"],
            vec!["--allow", "clippy::lint:__CLIPPY_HACKERY__"],
            vec!["--cap-lints", "force-warn"],
            vec!["--config", "/other"],
        ] {
            let selection = CompilationSelection {
                lint_args: args.into_iter().map(str::to_owned).collect(),
                ..CompilationSelection::default()
            };
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Clippy)
                    .is_err(),
                "{selection:?}"
            );
        }
        let mut selection = CompilationSelection {
            lint_args: vec!["-Awarnings".into(); MAX_VALUES],
            ..CompilationSelection::default()
        };
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .is_ok()
        );
        selection.packages.push("app".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .is_err()
        );
        selection.packages.clear();
        selection.lint_args = vec![format!("-A{}", "a".repeat(256)); MAX_VALUES];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .is_err()
        );
        selection.lint_args = vec![format!("-A{}", "a".repeat(257))];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .is_err()
        );
        selection.lint_args.clear();
        selection.test_args.push("--nocapture".into());
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Clippy)
                .is_err()
        );
    }

    #[test]
    fn test_runtime_and_compilation_selection_share_one_bounded_argument_budget() {
        let mut selection = CompilationSelection {
            test_args: vec!["--nocapture".into(); MAX_VALUES],
            ..CompilationSelection::default()
        };
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .is_ok()
        );
        selection.test_filter = Some("selected".into());
        assert!(selection.cargo_arguments(CompilationCommand::Test).is_err());
        selection.test_args.pop();
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .is_ok()
        );
        selection.packages.push("package".into());
        assert!(selection.cargo_arguments(CompilationCommand::Test).is_err());
        selection.packages.clear();
        selection.test_args = vec!["a".repeat(MAX_VALUE_BYTES); MAX_VALUES - 1];
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .is_err()
        );
        selection.test_args = vec!["a".repeat(MAX_VALUE_BYTES + 1)];
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .is_err()
        );
        for value in ["--config=bad", "filter\0", "filter\n"] {
            selection.test_args.clear();
            selection.test_filter = Some(value.into());
            assert!(selection.cargo_arguments(CompilationCommand::Test).is_err());
        }
        selection.test_filter = None;
        for value in ["test\0", "test\n"] {
            selection.test_args = vec![value.into()];
            assert!(
                selection
                    .runtime_arguments(CompilationCommand::Test)
                    .is_err()
            );
        }
        selection.test_args = vec![String::new()];
        assert_eq!(
            selection
                .runtime_arguments(CompilationCommand::Test)
                .unwrap(),
            ["--", ""]
        );
        for value in [
            json!({"doc":"true"}),
            json!({"no_run":1}),
            json!({"test_filter":["a"]}),
            json!({"test_args":"--nocapture"}),
            json!({"test_args":[true]}),
        ] {
            assert!(serde_json::from_value::<CompilationSelection>(value).is_err());
        }
    }
}
