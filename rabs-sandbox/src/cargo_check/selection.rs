//! One bounded Cargo compilation selection shared by planning and execution.
//!
//! These are target/feature selectors, not arbitrary Cargo arguments. The
//! driver supplies the retained manifest, offline/locked mode, compiler,
//! output directory and job budget itself. Both the nonexecuting unit-graph
//! query and the subsequent compilation use the same Cargo selection. Program,
//! test/benchmark harness and Clippy lint arguments form separate tails after the driver's
//! Cargo options. Nextest retains its runner selection separately from the
//! Cargo test compilation used by its nonexecuting unit-graph query.

use serde::{Deserialize, Serialize};
use std::io;

const MAX_VALUES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;

/// The captured Cargo command, separate from package and target selectors.
///
/// `Check` and `Build` compile without running the requested targets. `Test`
/// also runs Cargo's selected tests and doctests unless `no_run` is selected;
/// test outcomes are never action-cache results. `Nextest` runs the captured
/// nextest runner against Cargo-built tests, without doctests or cached test
/// outcomes. `Run` executes the selected
/// binary/example, and `Bench` runs selected benchmarks unless `no_run` is set.
/// Their bodies and outcomes are never cached. `Clippy` checks the selected
/// targets with the captured lint driver, whose results are never rustc cache
/// results. `Doc` renders documentation with captured rustdoc; documentation
/// output never establishes rustc cache authority. Cargo can run build scripts
/// and load procedural macros in every command. The validated unit graph
/// selects the required closed-worker boundary for compiler cache authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompilationCommand {
    #[default]
    Check,
    Build,
    Test,
    Nextest,
    Clippy,
    Doc,
    Run,
    Bench,
}

/// Standard input for the current Cargo invocation and its executed targets.
///
/// `Closed` supplies EOF. `Inherit` preserves the caller's nonterminal input;
/// services that do not forward stdin must refuse it. This is an execution
/// policy, not captured input bytes or authority to cache a program's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompilationStdin {
    Closed,
    Inherit,
}

impl CompilationCommand {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Build => "build",
            Self::Test => "test",
            Self::Nextest => "nextest",
            Self::Clippy => "clippy",
            Self::Doc => "doc",
            Self::Run => "run",
            Self::Bench => "bench",
        }
    }

    /// Resolve an optional input policy without changing an existing command's
    /// behavior. Only `run` and executing `bench` inherit input by default.
    /// Executing `test` or `nextest` may explicitly inherit input while retaining
    /// EOF by default. Nonexecuting commands and `--no-run` keep closed input.
    pub fn stdin_policy(
        self,
        no_run: bool,
        requested: Option<CompilationStdin>,
    ) -> io::Result<CompilationStdin> {
        let executes_with_input = self == Self::Run
            || (matches!(self, Self::Test | Self::Nextest | Self::Bench) && !no_run);
        match requested {
            Some(CompilationStdin::Inherit) if !executes_with_input => Err(invalid(
                "inherited stdin is supported only for run, test, nextest or bench execution",
            )),
            Some(policy) => Ok(policy),
            None if executes_with_input && !matches!(self, Self::Test | Self::Nextest) => {
                Ok(CompilationStdin::Inherit)
            }
            None => Ok(CompilationStdin::Closed),
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
    /// Nextest receives this as `--cargo-profile`, distinct from its runner profile.
    pub profile: Option<String>,
    /// Nextest's named runner profile from captured project configuration.
    /// This does not select the Cargo compilation profile or grant result caching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_profile: Option<String>,
    /// Explicit positive nextest parallelism. Omission preserves its configured
    /// test concurrency, including deliberately serial profiles. Compilation
    /// parallelism remains the driver's independent `--build-jobs` control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_threads: Option<u32>,
    /// Literal nextest filterset expressions. They select test execution only
    /// and must never narrow the Cargo graph used for compiler input capture.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filtersets: Vec<String>,
    /// Select documentation tests, only for the `Test` command.
    pub doc: bool,
    /// Compile Cargo's test or benchmark executables without running them.
    pub no_run: bool,
    /// Let Cargo run the remaining test or benchmark executables after one fails.
    pub no_fail_fast: bool,
    /// Cargo's optional positional test/benchmark filter, passed as one argument.
    pub test_filter: Option<String>,
    /// Literal test-harness arguments. These are appended after `--`, never
    /// interpreted as Cargo configuration, source, toolchain or output options.
    pub test_args: Vec<String>,
    /// Literal program arguments after `cargo run --`. These never become Cargo
    /// options and may contain empty strings, Unicode or control bytes other
    /// than NUL, which cannot be represented in a process argument.
    pub run_args: Vec<String>,
    /// Limit Clippy linting or documentation generation to selected packages.
    /// Cargo still compiles any dependencies those operations require.
    pub no_deps: bool,
    /// Include private items in generated documentation, only for `Doc`.
    pub document_private_items: bool,
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
        if self.doc && command != CompilationCommand::Test {
            return Err(invalid(
                "documentation tests require the Cargo test command",
            ));
        }
        if !matches!(
            command,
            CompilationCommand::Test | CompilationCommand::Nextest | CompilationCommand::Bench
        ) && (self.no_run
            || self.no_fail_fast
            || self.test_filter.is_some()
            || !self.test_args.is_empty())
        {
            return Err(invalid(
                "harness selection requires the Cargo test, nextest or bench command",
            ));
        }
        if command != CompilationCommand::Nextest
            && (self.runner_profile.is_some()
                || self.test_threads.is_some()
                || !self.filtersets.is_empty())
        {
            return Err(invalid("runner selection requires the nextest command"));
        }
        if self
            .runner_profile
            .as_ref()
            .is_some_and(|profile| !ordinary_name(profile))
        {
            return Err(invalid("invalid nextest runner profile name"));
        }
        if self
            .test_threads
            .is_some_and(|threads| !(1..=4096).contains(&threads))
        {
            return Err(invalid("nextest test threads must be between 1 and 4096"));
        }
        if self.filtersets.iter().any(|filter| {
            filter.trim().is_empty()
                || filter.len() > MAX_VALUE_BYTES
                || filter.starts_with('-')
                || filter.chars().any(char::is_control)
        }) {
            return Err(invalid("invalid nextest filterset expression"));
        }
        if command == CompilationCommand::Nextest && self.target.len() > 1 {
            return Err(invalid("nextest selects at most one compilation target"));
        }
        if command == CompilationCommand::Nextest && self.no_run && self.no_fail_fast {
            return Err(invalid("nextest --no-fail-fast requires test execution"));
        }
        if command != CompilationCommand::Run && !self.run_args.is_empty() {
            return Err(invalid("program arguments require the Cargo run command"));
        }
        if command == CompilationCommand::Run
            && (self.workspace
                || !self.exclude.is_empty()
                || self.packages.len() > 1
                || self.lib
                || self.bins
                || self.tests
                || self.examples
                || self.benches
                || self.all_targets
                || !self.test.is_empty()
                || !self.bench.is_empty()
                || self.bin.len() + self.example.len() > 1
                || self.target.len() > 1)
        {
            return Err(invalid(
                "Cargo run selects one package and one binary or example",
            ));
        }
        if self.no_deps
            && !matches!(
                command,
                CompilationCommand::Clippy | CompilationCommand::Doc
            )
        {
            return Err(invalid("--no-deps requires Cargo clippy or doc"));
        }
        if command != CompilationCommand::Clippy && !self.lint_args.is_empty() {
            return Err(invalid(
                "Clippy selection requires the Cargo clippy command",
            ));
        }
        if self.document_private_items && command != CompilationCommand::Doc {
            return Err(invalid("private documentation items require Cargo doc"));
        }
        if command == CompilationCommand::Doc
            && (self.tests
                || self.benches
                || self.all_targets
                || !self.test.is_empty()
                || !self.bench.is_empty())
        {
            return Err(invalid(
                "Cargo doc selects libraries, binaries or examples, not tests or benches",
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
        if command == CompilationCommand::Bench && self.release {
            return Err(invalid(
                "Cargo bench selects its compilation profile with --profile",
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
            + usize::from(self.runner_profile.is_some())
            + usize::from(self.test_threads.is_some())
            + self.filtersets.len()
            + usize::from(self.test_filter.is_some())
            + self.test_args.len()
            + self.run_args.len()
            + self.lint_args.len();
        if count > MAX_VALUES {
            return Err(invalid("Cargo compilation selection has too many values"));
        }
        let mut args = vec![command.as_str().to_owned()];
        if command == CompilationCommand::Nextest {
            args.push("run".into());
        }
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
            (self.document_private_items, "--document-private-items"),
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
            args.push(
                if command == CompilationCommand::Nextest {
                    "--cargo-profile"
                } else {
                    "--profile"
                }
                .into(),
            );
            args.push(profile.clone());
        }
        if let Some(profile) = &self.runner_profile {
            args.extend(["--profile".into(), profile.clone()]);
        }
        if let Some(threads) = self.test_threads {
            args.extend(["--test-threads".into(), threads.to_string()]);
        }
        for filter in &self.filtersets {
            args.extend(["--filterset".into(), filter.clone()]);
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
        if self
            .run_args
            .iter()
            .any(|arg| arg.len() > MAX_VALUE_BYTES || arg.contains('\0'))
        {
            return Err(invalid("invalid program argument"));
        }
        let tail = self.argument_tail(command);
        let runtime_bytes =
            tail.iter().map(String::len).sum::<usize>() + if tail.is_empty() { 0 } else { 2 };
        if args.iter().map(String::len).sum::<usize>() + runtime_bytes > MAX_ARGUMENT_BYTES {
            return Err(invalid(
                "Cargo compilation selection exceeds its argument byte budget",
            ));
        }
        Ok(args)
    }

    /// Derive the exact Cargo compilation selection used by `nextest run`.
    ///
    /// Nextest builds with `cargo test --no-run`; its runner profiles, filters,
    /// concurrency and emulated harness arguments never select Cargo units.
    /// The caller runs this selection with the captured Cargo executable and
    /// `CompilationCommand::Test`, then validates the graph as `Nextest` so
    /// project execution still requires the closed worker authority boundary.
    pub fn nextest_build_selection(&self) -> io::Result<Self> {
        self.cargo_arguments(CompilationCommand::Nextest)?;
        let mut compilation = self.clone();
        compilation.no_run = true;
        compilation.no_fail_fast = false;
        compilation.test_filter = None;
        compilation.test_args.clear();
        compilation.runner_profile = None;
        compilation.test_threads = None;
        compilation.filtersets.clear();
        Ok(compilation)
    }

    /// Construct the program, harness or Clippy lint tail after validating the entire
    /// selection, including its shared count and byte limits. Append this only
    /// after all driver-owned Cargo options. Unit-graph queries omit test-harness
    /// arguments, but retain Clippy lint arguments for the same driver invocation.
    pub fn runtime_arguments(&self, command: CompilationCommand) -> io::Result<Vec<String>> {
        self.cargo_arguments(command)?;
        let tail = self.argument_tail(command);
        if tail.is_empty() {
            return Ok(Vec::new());
        }
        Ok(std::iter::once("--".to_owned())
            .chain(tail.iter().cloned())
            .collect())
    }

    fn argument_tail(&self, command: CompilationCommand) -> &[String] {
        match command {
            CompilationCommand::Clippy => &self.lint_args,
            CompilationCommand::Run => &self.run_args,
            _ => &self.test_args,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stdin_policy_preserves_command_defaults_and_allows_explicit_eof() {
        use CompilationStdin::{Closed, Inherit};

        for (command, no_run, default, permits_inherit) in [
            (CompilationCommand::Run, false, Inherit, true),
            (CompilationCommand::Bench, false, Inherit, true),
            (CompilationCommand::Bench, true, Closed, false),
            (CompilationCommand::Test, false, Closed, true),
            (CompilationCommand::Test, true, Closed, false),
            (CompilationCommand::Nextest, false, Closed, true),
            (CompilationCommand::Nextest, true, Closed, false),
            (CompilationCommand::Check, false, Closed, false),
            (CompilationCommand::Build, false, Closed, false),
            (CompilationCommand::Clippy, false, Closed, false),
            (CompilationCommand::Doc, false, Closed, false),
        ] {
            assert_eq!(command.stdin_policy(no_run, None).unwrap(), default);
            assert_eq!(
                command
                    .stdin_policy(no_run, Some(CompilationStdin::Closed))
                    .unwrap(),
                CompilationStdin::Closed,
            );
            assert_eq!(
                command
                    .stdin_policy(no_run, Some(CompilationStdin::Inherit))
                    .is_ok(),
                permits_inherit,
                "{command:?}, no_run={no_run}",
            );
        }
    }

    #[test]
    fn stdin_policy_wire_values_are_typed_and_reject_unsupported_inputs() {
        for (name, policy) in [
            ("closed", CompilationStdin::Closed),
            ("inherit", CompilationStdin::Inherit),
        ] {
            assert_eq!(
                serde_json::from_value::<CompilationStdin>(json!(name)).unwrap(),
                policy
            );
            assert_eq!(serde_json::to_value(policy).unwrap(), json!(name));
        }
        for value in [
            json!("pipe"),
            json!("/dev/null"),
            json!("Closed"),
            json!(true),
            json!({}),
        ] {
            assert!(serde_json::from_value::<CompilationStdin>(value).is_err());
        }
    }

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
            ("nextest", CompilationCommand::Nextest),
            ("clippy", CompilationCommand::Clippy),
            ("doc", CompilationCommand::Doc),
            ("run", CompilationCommand::Run),
            ("bench", CompilationCommand::Bench),
        ] {
            let command: CompilationCommand = serde_json::from_value(json!(text)).unwrap();
            assert_eq!(command, expected);
            assert_eq!(serde_json::to_value(command).unwrap(), json!(text));
        }
        for value in [
            json!("rustdoc"),
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
    fn nextest_separates_runner_selection_from_cargo_compilation_and_graph_planning() {
        let selection = CompilationSelection {
            workspace: true,
            packages: vec!["app".into()],
            features: vec!["fast".into()],
            tests: true,
            target: vec!["x86_64-unknown-linux-gnu".into()],
            profile: Some("ci-build".into()),
            runner_profile: Some("ci-runner".into()),
            test_threads: Some(1),
            filtersets: vec![
                "package(app) & not(test(slow))".into(),
                "test(/^db::/)".into(),
            ],
            no_fail_fast: true,
            test_filter: Some("cache::".into()),
            test_args: vec!["--exact".into(), "--nocapture".into()],
            ..CompilationSelection::default()
        };
        let original = selection.clone();
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Nextest)
                .unwrap(),
            [
                "nextest",
                "run",
                "--workspace",
                "--tests",
                "--no-fail-fast",
                "--package",
                "app",
                "--features",
                "fast",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--cargo-profile",
                "ci-build",
                "--profile",
                "ci-runner",
                "--test-threads",
                "1",
                "--filterset",
                "package(app) & not(test(slow))",
                "--filterset",
                "test(/^db::/)",
                "cache::",
            ]
        );
        assert_eq!(
            selection
                .runtime_arguments(CompilationCommand::Nextest)
                .unwrap(),
            ["--", "--exact", "--nocapture"]
        );
        let planned = selection.nextest_build_selection().unwrap();
        assert_eq!(
            planned.cargo_arguments(CompilationCommand::Test).unwrap(),
            [
                "test",
                "--workspace",
                "--tests",
                "--no-run",
                "--package",
                "app",
                "--features",
                "fast",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--profile",
                "ci-build",
            ]
        );
        assert!(
            planned
                .runtime_arguments(CompilationCommand::Test)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            selection, original,
            "planning must retain exact runner intent"
        );
    }

    #[test]
    fn nextest_defaults_preserve_configured_parallelism_and_existing_command_wire_fields() {
        let selection = CompilationSelection::default();
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Nextest)
                .unwrap(),
            ["nextest", "run"]
        );
        assert_eq!(
            selection
                .nextest_build_selection()
                .unwrap()
                .cargo_arguments(CompilationCommand::Test)
                .unwrap(),
            ["test", "--no-run"]
        );
        let encoded = serde_json::to_value(&selection).unwrap();
        for field in ["runner_profile", "test_threads", "filtersets"] {
            assert!(encoded.get(field).is_none(), "old commands gained {field}");
        }
        let selected: CompilationSelection = serde_json::from_value(json!({
            "profile":"ci-build", "runner_profile":"ci-runner", "test_threads":1,
            "filtersets":["test(serial)"]
        }))
        .unwrap();
        assert_eq!(
            serde_json::from_value::<CompilationSelection>(
                serde_json::to_value(&selected).unwrap()
            )
            .unwrap(),
            selected
        );
        for count in [1, 4096] {
            let mut selected = selected.clone();
            selected.test_threads = Some(count);
            assert!(
                selected
                    .cargo_arguments(CompilationCommand::Nextest)
                    .is_ok()
            );
        }
    }

    #[test]
    fn nextest_runner_controls_cannot_select_other_commands_or_doctests() {
        for selection in [
            CompilationSelection {
                runner_profile: Some("ci".into()),
                ..Default::default()
            },
            CompilationSelection {
                test_threads: Some(1),
                ..Default::default()
            },
            CompilationSelection {
                filtersets: vec!["all()".into()],
                ..Default::default()
            },
        ] {
            for command in [
                CompilationCommand::Check,
                CompilationCommand::Build,
                CompilationCommand::Test,
                CompilationCommand::Clippy,
                CompilationCommand::Doc,
                CompilationCommand::Run,
                CompilationCommand::Bench,
            ] {
                assert!(selection.cargo_arguments(command).is_err(), "{command:?}");
            }
        }
        for selection in [
            CompilationSelection {
                no_run: true,
                no_fail_fast: true,
                ..Default::default()
            },
            CompilationSelection {
                doc: true,
                ..Default::default()
            },
            CompilationSelection {
                run_args: vec!["argument".into()],
                ..Default::default()
            },
            CompilationSelection {
                no_deps: true,
                ..Default::default()
            },
            CompilationSelection {
                lint_args: vec!["-Dwarnings".into()],
                ..Default::default()
            },
            CompilationSelection {
                target: vec![
                    "x86_64-unknown-linux-gnu".into(),
                    "aarch64-unknown-linux-gnu".into(),
                ],
                ..Default::default()
            },
        ] {
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Nextest)
                    .is_err()
            );
            assert!(selection.nextest_build_selection().is_err());
        }
        let compilation_only = CompilationSelection {
            no_run: true,
            ..Default::default()
        };
        assert_eq!(
            compilation_only
                .cargo_arguments(CompilationCommand::Nextest)
                .unwrap(),
            ["nextest", "run", "--no-run"]
        );
    }

    #[test]
    fn nextest_runner_values_and_harness_tail_share_one_bounded_argument_budget() {
        for profile in [
            "",
            "../ci",
            "--config",
            "ci\n",
            &"x".repeat(MAX_VALUE_BYTES + 1),
        ] {
            let selection = CompilationSelection {
                runner_profile: Some(profile.into()),
                ..Default::default()
            };
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Nextest)
                    .is_err()
            );
        }
        for threads in [0, 4097, u32::MAX] {
            let selection = CompilationSelection {
                test_threads: Some(threads),
                ..Default::default()
            };
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Nextest)
                    .is_err()
            );
        }
        for filter in [
            "",
            "   ",
            "--manifest-path=elsewhere",
            "all()\n",
            "test(\0)",
            &"x".repeat(MAX_VALUE_BYTES + 1),
        ] {
            let selection = CompilationSelection {
                filtersets: vec![filter.into()],
                ..Default::default()
            };
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Nextest)
                    .is_err()
            );
        }
        let mut selection = CompilationSelection {
            filtersets: vec!["all()".into(); MAX_VALUES - 2],
            runner_profile: Some("ci".into()),
            test_threads: Some(1),
            ..Default::default()
        };
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Nextest)
                .is_ok()
        );
        selection.test_args.push("--nocapture".into());
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Nextest)
                .is_err()
        );
        selection.test_args.clear();
        selection.filtersets = vec!["x".repeat(MAX_VALUE_BYTES); 16];
        assert!(
            selection
                .cargo_arguments(CompilationCommand::Nextest)
                .is_err()
        );
        for value in [
            json!({"runner_profile":true}),
            json!({"test_threads":-1}),
            json!({"test_threads":"num-cpus"}),
            json!({"filtersets":"all()"}),
            json!({"filtersets":[false]}),
        ] {
            assert!(serde_json::from_value::<CompilationSelection>(value).is_err());
        }
    }

    #[test]
    fn documentation_selects_rendered_targets_without_accepting_execution_controls() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "workspace":true, "exclude":["unpublished"], "features":["app/fast"],
            "lib":true, "bin":["tool"], "example":["sample"], "no_deps":true,
            "document_private_items":true, "target":["host-tuple"], "profile":"release"
        }))
        .unwrap();
        assert_eq!(
            selection.cargo_arguments(CompilationCommand::Doc).unwrap(),
            [
                "doc",
                "--workspace",
                "--lib",
                "--no-deps",
                "--document-private-items",
                "--exclude",
                "unpublished",
                "--features",
                "app/fast",
                "--bin",
                "tool",
                "--example",
                "sample",
                "--target",
                "host-tuple",
                "--profile",
                "release"
            ]
        );
        assert!(
            selection
                .runtime_arguments(CompilationCommand::Doc)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            serde_json::from_value::<CompilationSelection>(
                serde_json::to_value(&selection).unwrap()
            )
            .unwrap(),
            selection
        );
        for value in [
            json!({"tests":true}),
            json!({"test":["suite"]}),
            json!({"benches":true}),
            json!({"bench":["timing"]}),
            json!({"all_targets":true}),
            json!({"doc":true}),
            json!({"no_run":true}),
            json!({"no_fail_fast":true}),
            json!({"test_filter":"case"}),
            json!({"test_args":["--nocapture"]}),
            json!({"run_args":["argument"]}),
            json!({"lint_args":["-D", "warnings"]}),
        ] {
            let rejected: CompilationSelection = serde_json::from_value(value.clone()).unwrap();
            assert!(
                rejected.cargo_arguments(CompilationCommand::Doc).is_err(),
                "{value}"
            );
        }
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Clippy,
            CompilationCommand::Test,
            CompilationCommand::Run,
            CompilationCommand::Bench,
        ] {
            assert!(
                CompilationSelection {
                    document_private_items: true,
                    ..CompilationSelection::default()
                }
                .cargo_arguments(command)
                .is_err(),
                "{command:?}"
            );
        }
        assert!(
            serde_json::from_value::<CompilationSelection>(
                json!({"document_private_items":"true"})
            )
            .is_err()
        );
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
    fn run_program_arguments_remain_literal_after_driver_options() {
        let selection: CompilationSelection = serde_json::from_value(json!({
            "packages":["app@1.0.0"], "bin":["server"], "profile":"dev",
            "run_args":["", "雪", "--manifest-path=/not-cargo", "--no-run", "line\nvalue"]
        }))
        .unwrap();
        let mut args = selection.cargo_arguments(CompilationCommand::Run).unwrap();
        assert_eq!(
            args,
            [
                "run",
                "--package",
                "app@1.0.0",
                "--bin",
                "server",
                "--profile",
                "dev"
            ]
        );
        args.extend(["--offline".into(), "--locked".into()]);
        args.extend(
            selection
                .runtime_arguments(CompilationCommand::Run)
                .unwrap(),
        );
        assert_eq!(
            &args[7..],
            [
                "--offline",
                "--locked",
                "--",
                "",
                "雪",
                "--manifest-path=/not-cargo",
                "--no-run",
                "line\nvalue"
            ]
        );
        for command in [
            CompilationCommand::Check,
            CompilationCommand::Build,
            CompilationCommand::Test,
            CompilationCommand::Bench,
            CompilationCommand::Clippy,
        ] {
            assert!(selection.cargo_arguments(command).is_err());
        }
        for value in [
            "invalid\0argument".to_owned(),
            "a".repeat(MAX_VALUE_BYTES + 1),
        ] {
            assert!(
                CompilationSelection {
                    run_args: vec![value],
                    ..CompilationSelection::default()
                }
                .cargo_arguments(CompilationCommand::Run)
                .is_err()
            );
        }
        assert!(
            CompilationSelection {
                run_args: vec!["".into(); MAX_VALUES + 1],
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Run)
            .is_err()
        );
        assert!(
            CompilationSelection {
                run_args: vec!["a".repeat(MAX_VALUE_BYTES); 17],
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Run)
            .is_err()
        );
    }

    #[test]
    fn run_selects_one_runnable_target_without_harness_or_lint_authority() {
        for value in [
            json!({"workspace":true}),
            json!({"lib":true}),
            json!({"bins":true}),
            json!({"tests":true}),
            json!({"examples":true}),
            json!({"benches":true}),
            json!({"all_targets":true}),
            json!({"packages":["one","two"]}),
            json!({"bin":["one"],"example":["two"]}),
            json!({"bin":["one","two"]}),
            json!({"test":["test"]}),
            json!({"bench":["bench"]}),
            json!({"doc":true}),
            json!({"no_run":true}),
            json!({"no_fail_fast":true}),
            json!({"no_deps":true}),
            json!({"test_filter":"selected"}),
            json!({"test_args":["--exact"]}),
            json!({"lint_args":["-D","warnings"]}),
            json!({"target":["host-tuple","other"]}),
        ] {
            let selection: CompilationSelection = serde_json::from_value(value.clone()).unwrap();
            assert!(
                selection.cargo_arguments(CompilationCommand::Run).is_err(),
                "{value}"
            );
        }
        for value in [
            json!({}),
            json!({"packages":["app"]}),
            json!({"bin":["server"]}),
            json!({"example":["demo"]}),
            json!({"target":["host-tuple"],"release":true}),
        ] {
            let selection: CompilationSelection = serde_json::from_value(value.clone()).unwrap();
            assert!(
                selection.cargo_arguments(CompilationCommand::Run).is_ok(),
                "{value}"
            );
        }
    }

    #[test]
    fn bench_keeps_cargos_profile_and_harness_arguments_without_running_no_run() {
        assert_eq!(
            CompilationSelection::default()
                .cargo_arguments(CompilationCommand::Bench)
                .unwrap(),
            ["bench"]
        );
        let selection: CompilationSelection = serde_json::from_value(json!({
            "bench":["throughput"], "profile":"dev", "no_fail_fast":true,
            "test_filter":"selected", "test_args":["--exact", "", "--nocapture"]
        }))
        .unwrap();
        assert_eq!(
            selection
                .cargo_arguments(CompilationCommand::Bench)
                .unwrap(),
            [
                "bench",
                "--no-fail-fast",
                "--bench",
                "throughput",
                "--profile",
                "dev",
                "selected"
            ]
        );
        assert_eq!(
            selection
                .runtime_arguments(CompilationCommand::Bench)
                .unwrap(),
            ["--", "--exact", "", "--nocapture"]
        );
        assert_eq!(
            CompilationSelection {
                no_run: true,
                ..CompilationSelection::default()
            }
            .cargo_arguments(CompilationCommand::Bench)
            .unwrap(),
            ["bench", "--no-run"]
        );
        for value in [
            json!({"doc":true}),
            json!({"release":true}),
            json!({"run_args":["program"]}),
            json!({"lint_args":["-D","warnings"]}),
            json!({"no_deps":true}),
        ] {
            let selection: CompilationSelection = serde_json::from_value(value.clone()).unwrap();
            assert!(
                selection
                    .cargo_arguments(CompilationCommand::Bench)
                    .is_err(),
                "{value}"
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
