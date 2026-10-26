//! One bounded Cargo check selection shared by planning and execution.
//!
//! These are target/feature selectors, not arbitrary Cargo arguments. The
//! driver supplies the retained manifest, offline/locked mode, compiler,
//! output directory and job budget itself. Both the nonexecuting unit-graph
//! query and the subsequent check use this exact argument vector.

use serde::{Deserialize, Serialize};
use std::io;

const MAX_VALUES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;

/// Cargo's ordinary package, feature and target selection for a check.
///
/// An empty selection means Cargo's default targets and default members. The
/// legacy local profile explicitly supplies `lib: true` when its optional
/// selection field is absent. Unknown fields cannot become command options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckSelection {
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
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

impl CheckSelection {
    /// Construct the complete selected check prefix without host authority.
    ///
    /// Cargo remains the authority for package-spec, feature and target-name
    /// syntax. Values are passed as distinct argv entries, never shell text.
    /// Leading options, control bytes and oversized requests are refused here
    /// before any source capture or command planning can start.
    pub fn cargo_arguments(&self) -> io::Result<Vec<String>> {
        if !self.exclude.is_empty() && !self.workspace {
            return Err(invalid(
                "Cargo check exclusions require workspace selection",
            ));
        }
        let values = [
            ("--package", &self.packages),
            ("--exclude", &self.exclude),
            ("--features", &self.features),
            ("--bin", &self.bin),
            ("--test", &self.test),
            ("--example", &self.example),
            ("--bench", &self.bench),
        ];
        let count = values.iter().map(|(_, values)| values.len()).sum::<usize>();
        if count > MAX_VALUES {
            return Err(invalid("Cargo check selection has too many values"));
        }
        let mut args = vec!["check".to_owned()];
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
                    return Err(invalid("invalid Cargo check selection value"));
                }
                args.push(option.to_owned());
                args.push(value.clone());
            }
        }
        if args.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_BYTES {
            return Err(invalid(
                "Cargo check selection exceeds its argument byte budget",
            ));
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_selection_preserves_cargos_default_member_and_target_selection() {
        assert_eq!(
            CheckSelection::default().cargo_arguments().unwrap(),
            ["check"]
        );
        assert_eq!(
            CheckSelection {
                lib: true,
                ..CheckSelection::default()
            }
            .cargo_arguments()
            .unwrap(),
            ["check", "--lib"]
        );
    }

    #[test]
    fn package_features_and_named_targets_are_literal_cargo_arguments() {
        let selection: CheckSelection = serde_json::from_value(json!({
            "workspace":true, "exclude":["integration-*"],
            "packages":["core@1.0.0", "app"],
            "features":["app/fast,core/serde", "core/std"],
            "no_default_features":true, "release":true,
            "bin":["server", "cli"], "test":["roundtrip"],
            "example":["client"], "bench":["throughput"]
        }))
        .unwrap();
        assert_eq!(
            selection.cargo_arguments().unwrap(),
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
                serde_json::from_value::<CheckSelection>(selection).is_err(),
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
            let selection = CheckSelection {
                features: vec![value.into()],
                ..CheckSelection::default()
            };
            assert!(selection.cargo_arguments().is_err(), "{value:?}");
        }
    }

    #[test]
    fn argument_limits_apply_to_the_whole_selection_and_exclusions_require_workspace() {
        let mut selection = CheckSelection {
            features: vec!["feature".into(); MAX_VALUES],
            ..CheckSelection::default()
        };
        assert!(selection.cargo_arguments().is_ok());
        selection.packages.push("package".into());
        assert!(selection.cargo_arguments().is_err());
        selection.packages.clear();
        selection.features = vec!["a".repeat(MAX_VALUE_BYTES); MAX_VALUES];
        assert!(selection.cargo_arguments().is_err());
        selection.features = vec!["a".repeat(MAX_VALUE_BYTES + 1)];
        assert!(selection.cargo_arguments().is_err());
        selection.features.clear();
        selection.exclude.push("excluded".into());
        assert!(selection.cargo_arguments().is_err());
        selection.workspace = true;
        assert!(selection.cargo_arguments().is_ok());
    }
}
