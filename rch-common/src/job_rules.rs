//! Explicit, default-off delegation rules for non-compilation jobs.
//!
//! Match literal argv, never shell text or normalized executable basenames.
//! The caller keeps ordinary compilation classification ahead of these rules.
//! A match supplies the original argv and selected result roots to the existing
//! job execution rail; filesystem and worker capability checks still run there.

use crate::types::JobsConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// One operator-authorized job interception rule.
///
/// Unknown fields are errors: a misspelled safety constraint must not silently
/// turn into a broader rule. Prefixes and required flags compare exact argv
/// words, and rule order determines the first match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobRule {
    pub name: String,
    pub argv_prefix: Vec<String>,
    #[serde(default)]
    pub required_flags: Vec<String>,
    #[serde(default)]
    pub result_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub require_tools: Vec<String>,
    /// An output directory option, such as "--output" or "-o".
    /// Requires one default result root, which an explicit option replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_flag: Option<String>,
}

/// A matched rule with literal argv and validated, resolved output roots.
#[derive(Debug, Clone)]
pub struct JobRuleMatch<'a> {
    pub rule: &'a JobRule,
    pub argv: Vec<String>,
    pub result_dirs: Vec<PathBuf>,
}

/// Validate rule configuration without executing commands or touching paths.
///
/// This also validates disabled rules, so enabling a previously configured rule
/// cannot activate malformed matching or output constraints.
///
/// # Errors
/// Returns the offending rule and invalid constraint.
pub fn validate(jobs: &JobsConfig) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for (index, rule) in jobs.rules.iter().enumerate() {
        let prefix = format!("jobs.rules[{index}]");
        if rule.name.is_empty()
            || !rule.name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(format!(
                "{prefix}.name must use nonempty ASCII letters, digits, - _ ."
            ));
        }
        if !names.insert(rule.name.as_str()) {
            return Err(format!("{prefix}.name duplicates rule {:?}", rule.name));
        }
        validate_rule(rule).map_err(|reason| format!("{prefix} ({:?}): {reason}", rule.name))?;
    }
    Ok(())
}

fn validate_rule(rule: &JobRule) -> Result<(), String> {
    let Some(executable) = rule.argv_prefix.first() else {
        return Err("argv_prefix must contain an executable".to_string());
    };
    if !literal_executable(executable) || cargo_rabs_invocation(&rule.argv_prefix) {
        return Err(
            "argv_prefix must start with a literal executable, without shell wrappers, assignments, traversal, or RCH helper recursion"
                .to_string(),
        );
    }
    if rule
        .argv_prefix
        .iter()
        .any(|word| word.chars().any(char::is_control))
    {
        return Err("argv_prefix may not contain control characters".to_string());
    }
    for flag in &rule.required_flags {
        if !option_name(flag) {
            return Err(format!(
                "required_flags entry {flag:?} must be an exact long option or single-letter short option"
            ));
        }
    }
    for tool in &rule.require_tools {
        crate::tool_requirement::validate(tool)
            .map_err(|reason| format!("invalid require_tools entry {tool:?}: {reason}"))?;
    }
    normalized_result_dirs(&rule.result_dirs)?;
    if let Some(flag) = &rule.output_flag {
        if !option_name(flag) {
            return Err(
                "output_flag must be one long option (such as --output) or one short option (such as -o)"
                    .to_string(),
            );
        }
        if rule.result_dirs.len() != 1 {
            return Err("output_flag requires exactly one default result_dirs entry".to_string());
        }
    }
    Ok(())
}

/// Match the first configured rule against a literal simple command.
///
/// Disabled rules, unrecognized prefixes and shell expressions return no match.
/// An invalid rule or output override returns an error rather than trying a
/// broader rule or losing the output constraint. Nothing after "--" is treated
/// as a required flag or output option.
///
/// # Errors
/// Returns a configuration error or an unsafe/ambiguous output override.
pub fn match_command<'a>(
    jobs: &'a JobsConfig,
    command: &str,
) -> Result<Option<JobRuleMatch<'a>>, String> {
    if !jobs.intercept_enabled || jobs.rules.is_empty() {
        return Ok(None);
    }
    validate(jobs)?;
    let Some(argv) = literal_argv(command) else {
        return Ok(None);
    };
    let option_end = argv.iter().position(|word| word == "--").unwrap_or(argv.len());
    for rule in &jobs.rules {
        if !argv.starts_with(&rule.argv_prefix)
            || !rule
                .required_flags
                .iter()
                .all(|flag| argv[1..option_end].contains(flag))
        {
            continue;
        }
        let result_dirs = resolve_result_dirs(rule, &argv[1..option_end])
            .map_err(|reason| format!("job rule {:?}: {reason}", rule.name))?;
        return Ok(Some(JobRuleMatch {
            rule,
            argv,
            result_dirs,
        }));
    }
    Ok(None)
}

fn option_name(value: &str) -> bool {
    if let Some(name) = value.strip_prefix("--") {
        !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
            })
    } else {
        value.len() == 2
            && value.starts_with('-')
            && value.as_bytes()[1].is_ascii_alphabetic()
    }
}

fn literal_executable(value: &str) -> bool {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('/')
        || value.contains(['=', '\\'])
        || value.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || value.split('/').any(|part| part == "..")
    {
        return false;
    }
    let Some(basename) = Path::new(value).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    // These are control syntax/indirection, not direct job executables.
    // A quoted shell program is still a shell program; never infer its payload.
    let basename = basename.to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    !matches!(
        basename,
        "if" | "then"
            | "else"
            | "elif"
            | "fi"
            | "for"
            | "while"
            | "until"
            | "do"
            | "done"
            | "case"
            | "esac"
            | "in"
            | "function"
            | "select"
            | "coproc"
            | "time"
            | "eval"
            | "source"
            | "exec"
            | "command"
            | "builtin"
            | "env"
            | "sh"
            | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "fish"
            | "csh"
            | "tcsh"
            | "pwsh"
            | "powershell"
            | "cmd"
            | "rch"
            | "rchd"
            | "rch-wkr"
            | "cargo-rabs"
            | "rabs-cargo"
            | "rabsd"
            | "rabs-wrap"
            | "rabs-wkr"
            | "rabs-recover"
            | "rabs-cargo-root"
    )
}

fn cargo_rabs_invocation(argv: &[String]) -> bool {
    let Some(executable) = argv.first() else {
        return false;
    };
    let Some(basename) = Path::new(executable).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !basename.eq_ignore_ascii_case("cargo")
        && !basename.eq_ignore_ascii_case("cargo.exe")
    {
        return false;
    }
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--color" | "--config" | "-C" | "-Z" => {
                let _ = args.next();
            }
            "--" => return args.next().is_some_and(|word| word == "rabs"),
            _ if arg.starts_with('-') || arg.starts_with('+') => {}
            _ => return arg == "rabs",
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quoting {
    None,
    Single,
    Double,
}

/// shell_words is an argv decoder, not a shell safety parser. Check the source
/// first so expansion, operators, comments and multiline control cannot be
/// converted into innocent-looking literal arguments.
fn literal_argv(command: &str) -> Option<Vec<String>> {
    if command.chars().any(|ch| ch.is_control() && ch != '\t') {
        return None;
    }
    let mut quoting = Quoting::None;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match quoting {
            Quoting::Single => {
                if ch == '\'' {
                    quoting = Quoting::None;
                }
            }
            Quoting::Double => match ch {
                '"' => quoting = Quoting::None,
                '$' | '\u{0060}' => return None,
                '\\' => {
                    let _ = chars.next()?;
                }
                _ => {}
            },
            Quoting::None => match ch {
                '\'' => quoting = Quoting::Single,
                '"' => quoting = Quoting::Double,
                '\\' => {
                    let _ = chars.next()?;
                }
                '$' | '\u{0060}' | '|' | '&' | ';' | '<' | '>' | '(' | ')' | '{' | '}' | '['
                | ']' | '*' | '?' | '~' | '#' | '!' => return None,
                _ => {}
            },
        }
    }
    if quoting != Quoting::None {
        return None;
    }
    let argv = shell_words::split(command).ok()?;
    if !argv.first().is_some_and(|word| literal_executable(word)) || cargo_rabs_invocation(&argv) {
        return None;
    }
    Some(argv)
}

fn normalize_result_dir(path: &Path) -> Result<PathBuf, String> {
    let value = path
        .to_str()
        .ok_or("result_dirs must contain only UTF-8 paths")?;
    if !value.is_ascii()
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
    {
        return Err(
            "result_dirs must be ASCII without backslashes, colons, or control characters"
                .to_string(),
        );
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(
                    "result_dirs must be repository-relative without parent traversal"
                        .to_string(),
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err("result_dirs must not be empty or the repository root".to_string());
    }
    Ok(normalized)
}

fn normalized_result_dirs(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut normalized: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths {
        let path = normalize_result_dir(path)?;
        if normalized
            .iter()
            .any(|prior| path.starts_with(prior) || prior.starts_with(&path))
        {
            return Err("result_dirs must not duplicate or overlap another result root".to_string());
        }
        normalized.push(path);
    }
    Ok(normalized)
}

fn resolve_result_dirs(rule: &JobRule, options: &[String]) -> Result<Vec<PathBuf>, String> {
    let Some(flag) = &rule.output_flag else {
        return normalized_result_dirs(&rule.result_dirs);
    };
    let mut override_dir = None;
    let mut words = options.iter();
    while let Some(word) = words.next() {
        let value = if word == flag {
            let value = words
                .next()
                .ok_or_else(|| format!("{flag} requires an output directory"))?;
            if value.starts_with('-') {
                return Err(format!("{flag} requires a directory before the next option"));
            }
            Some(value.as_str())
        } else if flag.starts_with("--") {
            word.strip_prefix(flag.as_str())
                .and_then(|suffix| suffix.strip_prefix('='))
        } else {
            let suffix = word
                .strip_prefix(flag.as_str())
                .filter(|suffix| !suffix.is_empty());
            if suffix.is_some_and(|value| value.starts_with('=')) {
                return Err(format!(
                    "{flag}=DIR has tool-dependent semantics; use {flag} DIR instead"
                ));
            }
            suffix
        };
        if let Some(value) = value {
            if override_dir.is_some() {
                return Err(format!("{flag} must appear at most once"));
            }
            override_dir = Some(normalize_result_dir(Path::new(value))?);
        }
    }
    match override_dir {
        Some(path) => Ok(vec![path]),
        None => normalized_result_dirs(&rule.result_dirs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RchConfig;

    fn rule(name: &str) -> JobRule {
        JobRule {
            name: name.to_string(),
            argv_prefix: vec!["cargo".to_string(), "mutants".to_string()],
            required_flags: Vec::new(),
            result_dirs: vec![PathBuf::from("mutants.out")],
            require_tools: vec!["cargo-mutants".to_string()],
            output_flag: None,
        }
    }

    fn enabled(rule: JobRule) -> JobsConfig {
        JobsConfig {
            intercept_enabled: true,
            rules: vec![rule],
            ..JobsConfig::default()
        }
    }

    #[test]
    fn rules_are_default_off_and_empty_configuration_is_unchanged() {
        let empty: RchConfig = toml::from_str("").unwrap();
        assert!(!empty.jobs.intercept_enabled);
        assert!(empty.jobs.rules.is_empty());
        assert!(
            match_command(&empty.jobs, "cargo mutants")
                .unwrap()
                .is_none()
        );
        let config = JobsConfig {
            rules: vec![rule("mutants")],
            ..JobsConfig::default()
        };
        assert!(match_command(&config, "cargo mutants").unwrap().is_none());
        let no_rules = JobsConfig {
            intercept_enabled: true,
            ..JobsConfig::default()
        };
        assert!(
            match_command(&no_rules, "cargo mutants")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn schema_preserves_constraints_and_rejects_misspelled_fields() {
        let text = r#"
[jobs]
intercept_enabled = true
required_tools = ["node@26.7.0"]
[[jobs.rules]]
name = "gate"
argv_prefix = ["my-gate", "gate"]
required_flags = ["--mutation"]
result_dirs = [".gate-reports"]
require_tools = ["my-gate"]
output_flag = "--output"
"#;
        let config: RchConfig = toml::from_str(text).unwrap();
        validate(&config.jobs).unwrap();
        let back: RchConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(config.jobs.rules, back.jobs.rules);
        assert_eq!(config.jobs.required_tools, ["node@26.7.0"]);
        for unknown in ["argv_prefx", "required_flag", "output_falg"] {
            let invalid = format!("{text}\n{unknown} = \"anything\"\n");
            assert!(toml::from_str::<RchConfig>(&invalid).is_err());
        }
    }

    #[test]
    fn matching_is_exact_and_does_not_unwrap_or_match_executable_basenames() {
        let config = enabled(rule("mutants"));
        for command in [
            "cargo mutants",
            "cargo mutants --timeout 60",
            "'cargo' 'mutants' --in-place",
        ] {
            let matched = match_command(&config, command).unwrap().unwrap();
            assert_eq!(matched.rule.name, "mutants");
            assert_eq!(matched.rule.require_tools, ["cargo-mutants"]);
            assert_eq!(matched.result_dirs, [PathBuf::from("mutants.out")]);
        }
        for command in [
            "cargo mutants-other",
            "my-cargo mutants",
            "/usr/bin/cargo mutants",
            "cargo +nightly mutants",
            "env cargo mutants",
            "timeout 60 cargo mutants",
            "echo cargo mutants",
            "RUST_LOG=debug cargo mutants",
        ] {
            assert!(match_command(&config, command).unwrap().is_none(), "{command}");
        }
        let mut absolute = rule("absolute");
        absolute.argv_prefix[0] = "/opt/tools/cargo".to_string();
        let config = enabled(absolute);
        assert!(
            match_command(&config, "/opt/tools/cargo mutants")
                .unwrap()
                .is_some()
        );
        assert!(match_command(&config, "cargo mutants").unwrap().is_none());
    }

    #[test]
    fn required_flags_must_be_exact_and_precede_the_end_of_options() {
        let mut gate = rule("gate");
        gate.argv_prefix = vec!["my-gate".to_string(), "gate".to_string()];
        gate.required_flags = vec!["--mutation".to_string(), "-v".to_string()];
        let config = enabled(gate);
        assert!(
            match_command(&config, "my-gate gate -v --mutation -- package")
                .unwrap()
                .is_some()
        );
        for command in [
            "my-gate gate --mutation",
            "my-gate gate -v --mutation=false",
            "my-gate gate -v --mutation-report",
            "my-gate gate -v -- --mutation",
            "my-gate gate --mutation -- -v",
        ] {
            assert!(match_command(&config, command).unwrap().is_none(), "{command}");
        }
    }

    #[test]
    fn quoted_and_escaped_literals_keep_their_original_argv() {
        let config = enabled(rule("mutants"));
        for (command, expected) in [
            ("cargo mutants 'a file'", "a file"),
            ("cargo mutants \"a file\"", "a file"),
            ("cargo mutants a\\ file", "a file"),
            ("cargo mutants 'a;$(exit 1)*'", "a;$(exit 1)*"),
            ("cargo mutants \"a;*\"", "a;*"),
            ("cargo mutants \\$literal", "$literal"),
            ("cargo mutants a\\;b", "a;b"),
            ("cargo mutants ''", ""),
        ] {
            let matched = match_command(&config, command).unwrap().unwrap();
            assert_eq!(matched.argv, ["cargo", "mutants", expected], "{command}");
        }
    }

    #[test]
    fn shell_effects_never_become_literal_job_arguments() {
        let config = enabled(rule("mutants"));
        for command in [
            "cargo mutants; echo done",
            "cargo mutants && echo done",
            "cargo mutants || echo done",
            "cargo mutants | tee log",
            "cargo mutants > report",
            "cargo mutants 2>&1",
            "cargo mutants &",
            "cargo mutants $(touch injected)",
            "cargo mutants \u{0060}pwd\u{0060}",
            "cargo mutants $HOME",
            "cargo mutants \"$HOME\"",
            "cargo mutants \"\u{0060}pwd\u{0060}\"",
            "cargo mutants $'literal'",
            "cargo mutants *.rs",
            "cargo mutants a?.rs",
            "cargo mutants [ab].rs",
            "cargo mutants {a,b}",
            "cargo mutants ~/source",
            "cargo mutants # comment",
            "cargo mutants\ntrue",
            "cargo mutants\rtrue",
            "cargo mutants\0",
            "cargo mutants 'unterminated",
            "cargo mutants \"unterminated",
            "cargo mutants \\",
        ] {
            assert!(match_command(&config, command).unwrap().is_none(), "{command:?}");
        }
        let matched = match_command(&config, "cargo\tmutants").unwrap().unwrap();
        assert_eq!(matched.argv, ["cargo", "mutants"]);
    }

    #[test]
    fn unsafe_executable_prefixes_cannot_enable_recursion_or_shell_indirection() {
        for executable in [
            "",
            "RUST_LOG=debug",
            "rch",
            "/usr/local/bin/rch",
            "RCH.exe",
            "rchd",
            "rch-wkr",
            "cargo-rabs",
            "rabs-cargo",
            "rabsd",
            "rabs-wrap",
            "rabs-wkr",
            "rabs-recover",
            "rabs-cargo-root",
            "eval",
            "env",
            "/bin/bash",
            "sh",
            "command",
            "exec",
            "source",
            "if",
            "for",
            "../gate",
            "/opt/../bin/gate",
            "./my gate",
        ] {
            let mut candidate = rule("invalid");
            candidate.argv_prefix = vec![executable.to_string()];
            let config = enabled(candidate);
            assert!(validate(&config).is_err(), "{executable:?}");
            assert!(match_command(&config, "cargo mutants").is_err());
        }
    }

    #[test]
    fn cargo_subcommand_recursion_cannot_match_a_broad_cargo_rule() {
        let mut candidate = rule("cargo-jobs");
        candidate.argv_prefix = vec!["cargo".to_string()];
        let config = enabled(candidate);
        for command in [
            "cargo rabs check",
            "cargo +nightly rabs check",
            "cargo --color never rabs check",
            "cargo -Z script rabs check",
            "cargo -- rabs check",
        ] {
            assert!(match_command(&config, command).unwrap().is_none(), "{command}");
        }
        assert!(
            match_command(&config, "cargo mutants --label rabs")
                .unwrap()
                .is_some()
        );
        let mut candidate = rule("recursive-prefix");
        candidate.argv_prefix = vec!["cargo".to_string(), "rabs".to_string()];
        assert!(validate(&enabled(candidate)).is_err());
    }

    #[test]
    fn malformed_rule_constraints_and_duplicate_names_are_rejected() {
        let mut duplicate = enabled(rule("same"));
        duplicate.rules.push(rule("same"));
        assert!(validate(&duplicate).unwrap_err().contains("duplicates"));
        for name in ["", "space name", "bad\nname", "gâté"] {
            let mut candidate = rule("valid");
            candidate.name = name.to_string();
            assert!(validate(&enabled(candidate)).is_err());
        }
        let mut candidate = rule("empty");
        candidate.argv_prefix.clear();
        assert!(validate(&enabled(candidate)).is_err());
        let mut candidate = rule("control");
        candidate.argv_prefix.push("bad\0argument".to_string());
        assert!(validate(&enabled(candidate)).is_err());
        for flag in ["", "--", "-", "mutation", "--bad flag", "--output=x", "-ab"] {
            let mut candidate = rule("flag");
            candidate.required_flags = vec![flag.to_string()];
            assert!(validate(&enabled(candidate)).is_err(), "{flag:?}");
        }
    }

    #[test]
    fn result_roots_reject_escape_and_alias_forms_without_touching_files() {
        for path in [
            "", ".", "./", "../reports", "reports/../outside", "/tmp/reports",
            "C:/reports", "reports\\outside", "repórts", "reports\nother",
        ] {
            let mut candidate = rule("root");
            candidate.result_dirs = vec![PathBuf::from(path)];
            assert!(validate(&enabled(candidate)).is_err(), "{path:?}");
        }
        let mut candidate = rule("normalized");
        candidate.result_dirs = vec![PathBuf::from("./reports//mutation")];
        let config = enabled(candidate);
        let matched = match_command(&config, "cargo mutants").unwrap().unwrap();
        assert_eq!(matched.result_dirs, [PathBuf::from("reports/mutation")]);

        for roots in [
            ["reports", "reports"],
            ["reports", "./reports"],
            ["reports", "reports/mutation"],
            ["reports/mutation", "reports"],
        ] {
            let mut candidate = rule("overlap");
            candidate.result_dirs = roots.iter().map(PathBuf::from).collect();
            assert!(validate(&enabled(candidate)).is_err(), "{roots:?}");
        }
    }

    #[test]
    fn tool_constraints_use_the_existing_verified_tool_contract() {
        for tool in ["cargo-mutants", "g++", "node@26.7.0", "bun@1.3.0"] {
            let mut candidate = rule("tool");
            candidate.require_tools = vec![tool.to_string()];
            validate(&enabled(candidate)).unwrap();
        }
        for tool in ["", "cargo mutants", "tool/path", "node@latest", "rust@1.80.0"] {
            let mut candidate = rule("tool");
            candidate.require_tools = vec![tool.to_string()];
            assert!(validate(&enabled(candidate)).is_err(), "{tool:?}");
        }
    }

    #[test]
    fn first_matching_rule_is_deterministic_without_broadening_on_error() {
        let mut first = rule("first");
        first.output_flag = Some("--output".to_string());
        let mut second = rule("second");
        second.result_dirs = vec![PathBuf::from("other.out")];
        let mut config = enabled(first);
        config.rules.push(second);
        let matched = match_command(&config, "cargo mutants").unwrap().unwrap();
        assert_eq!(matched.rule.name, "first");
        assert!(match_command(&config, "cargo mutants --output=../escape").is_err());
        config.rules[0].required_flags = vec!["--special".to_string()];
        let matched = match_command(&config, "cargo mutants").unwrap().unwrap();
        assert_eq!(matched.rule.name, "second");
    }

    #[test]
    fn long_output_options_replace_one_root_and_preserve_argv() {
        let mut candidate = rule("output");
        candidate.output_flag = Some("--output".to_string());
        let config = enabled(candidate);
        for (command, expected) in [
            ("cargo mutants", "mutants.out"),
            ("cargo mutants --output reports/mutation", "reports/mutation"),
            ("cargo mutants --output=reports/mutation", "reports/mutation"),
            ("cargo mutants --output 'reports/a run'", "reports/a run"),
            ("cargo mutants --output=./reports//run", "reports/run"),
            ("cargo mutants --output-extra=elsewhere", "mutants.out"),
            ("cargo mutants -- --output=../ignored", "mutants.out"),
        ] {
            let matched = match_command(&config, command).unwrap().unwrap();
            assert_eq!(matched.result_dirs, [PathBuf::from(expected)], "{command}");
            assert_eq!(matched.argv, shell_words::split(command).unwrap());
        }
    }

    #[test]
    fn short_output_options_accept_attached_and_separate_values() {
        let mut candidate = rule("short-output");
        candidate.output_flag = Some("-o".to_string());
        let config = enabled(candidate);
        for command in ["cargo mutants -oreports", "cargo mutants -o reports"] {
            let matched = match_command(&config, command).unwrap().unwrap();
            assert_eq!(matched.result_dirs, [PathBuf::from("reports")]);
        }
        let matched = match_command(&config, "cargo mutants --other reports")
            .unwrap()
            .unwrap();
        assert_eq!(matched.result_dirs, [PathBuf::from("mutants.out")]);
        for command in [
            "cargo mutants -o",
            "cargo mutants -o=",
            "cargo mutants -o=reports",
            "cargo mutants -o --",
            "cargo mutants -o --verbose",
            "cargo mutants -o../outside",
            "cargo mutants -o/tmp/reports",
            "cargo mutants -oreports -o reports",
        ] {
            assert!(match_command(&config, command).is_err(), "{command}");
        }
    }

    #[test]
    fn unsafe_or_ambiguous_output_overrides_are_errors() {
        let mut candidate = rule("output");
        candidate.output_flag = Some("--output".to_string());
        let config = enabled(candidate);
        for command in [
            "cargo mutants --output",
            "cargo mutants --output --",
            "cargo mutants --output --verbose",
            "cargo mutants --output=",
            "cargo mutants --output ''",
            "cargo mutants --output .",
            "cargo mutants --output=../outside",
            "cargo mutants --output=reports/../outside",
            "cargo mutants --output=/tmp/reports",
            "cargo mutants --output=C:/reports",
            "cargo mutants --output 'reports\\outside'",
            "cargo mutants --output=reports --output reports",
            "cargo mutants --output=first --output=second",
        ] {
            assert!(match_command(&config, command).is_err(), "{command}");
        }
    }

    #[test]
    fn output_flag_configuration_requires_one_unambiguous_default_root() {
        for roots in [vec![], vec![PathBuf::from("one"), PathBuf::from("two")]] {
            let mut candidate = rule("output");
            candidate.result_dirs = roots;
            candidate.output_flag = Some("--output".to_string());
            assert!(validate(&enabled(candidate)).is_err());
        }
        for flag in ["", "--", "-", "output", "--output=", "--out dir", "-ab"] {
            let mut candidate = rule("output");
            candidate.output_flag = Some(flag.to_string());
            assert!(validate(&enabled(candidate)).is_err(), "{flag:?}");
        }
    }
}
