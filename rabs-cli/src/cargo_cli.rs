//! Exact operator options and bounded native Cargo selectors.

use rabs_sandbox::cargo_check::{CompilationCommand, CompilationSelection, CompilationStdin};
use std::ffi::OsString;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Local,
    Remote,
}

#[derive(Debug)]
pub(crate) enum Input {
    Policy(CompilationStdin),
    File(String),
}

#[derive(Debug)]
pub(crate) struct Options {
    pub mode: Mode,
    pub profile: OsString,
    pub daemon: Option<OsString>,
    pub input: Option<Input>,
    pub selected: Option<(CompilationCommand, CompilationSelection)>,
}

pub(crate) enum Invocation {
    Help,
    Run(Box<Options>),
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

pub(crate) fn parse(arguments: &[OsString]) -> io::Result<Invocation> {
    let mut mode = None;
    let mut profile = None;
    let mut daemon = None;
    let mut input = None;
    let mut at = 0;
    while at < arguments.len() {
        let argument = &arguments[at];
        if argument == "--help" || argument == "-h" {
            return Ok(Invocation::Help);
        }
        if argument == "--" {
            at += 1;
            break;
        }
        if !argument.as_encoded_bytes().starts_with(b"-") {
            break;
        }
        let (name, inline) = argument
            .to_str()
            .and_then(|text| text.split_once('='))
            .map_or((argument.as_os_str(), None), |(name, value)| {
                (std::ffi::OsStr::new(name), Some(OsString::from(value)))
            });
        if !matches!(
            name.to_str(),
            Some("--local" | "--remote" | "--rabsd" | "--stdin" | "--stdin-file")
        ) {
            return Err(invalid("unknown frontend option; use --help"));
        }
        let value = if let Some(value) = inline {
            value
        } else {
            at += 1;
            arguments
                .get(at)
                .filter(|value| !value.as_encoded_bytes().starts_with(b"-"))
                .cloned()
                .ok_or_else(|| invalid("frontend option requires a value"))?
        };
        if value.is_empty() {
            return Err(invalid("frontend option requires a nonempty value"));
        }
        match name.to_str() {
            Some("--local" | "--remote") => {
                if mode.is_some() {
                    return Err(invalid("select exactly one local or remote profile"));
                }
                mode = Some(if name == "--local" {
                    Mode::Local
                } else {
                    Mode::Remote
                });
                profile = Some(value);
            }
            Some("--rabsd") => {
                if daemon.replace(value).is_some() {
                    return Err(invalid("--rabsd may be selected only once"));
                }
            }
            Some("--stdin" | "--stdin-file") => {
                if input.is_some() {
                    return Err(invalid("select stdin or stdin-file only once"));
                }
                let value = value
                    .into_string()
                    .map_err(|_| invalid("stdin selection must be UTF-8"))?;
                input = Some(if name == "--stdin-file" {
                    Input::File(value)
                } else {
                    Input::Policy(match value.as_str() {
                        "closed" => CompilationStdin::Closed,
                        "inherit" => CompilationStdin::Inherit,
                        _ => return Err(invalid("stdin policy must be closed or inherit")),
                    })
                });
            }
            _ => return Err(invalid("unknown frontend option")),
        }
        at += 1;
    }
    let mode = mode.ok_or_else(|| invalid("select --local PROFILE or --remote PROFILE"))?;
    let profile = profile.ok_or_else(|| invalid("profile path is missing"))?;
    let selected = if at == arguments.len() {
        None
    } else {
        Some(selection(&arguments[at..])?)
    };
    Ok(Invocation::Run(Box::new(Options {
        mode,
        profile,
        daemon,
        input,
        selected,
    })))
}

fn selection(arguments: &[OsString]) -> io::Result<(CompilationCommand, CompilationSelection)> {
    let arguments: Vec<_> = arguments
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .ok_or_else(|| invalid("Cargo selectors must be UTF-8"))
        })
        .collect::<io::Result<_>>()?;
    let command = match arguments[0] {
        "check" => CompilationCommand::Check,
        "build" => CompilationCommand::Build,
        "clippy" => CompilationCommand::Clippy,
        "doc" => CompilationCommand::Doc,
        "test" => CompilationCommand::Test,
        "run" => CompilationCommand::Run,
        "bench" => CompilationCommand::Bench,
        _ => return Err(invalid("unsupported canonical Cargo command")),
    };
    let mut selected = CompilationSelection::default();
    let mut at = 1;
    while at < arguments.len() {
        let argument = arguments[at];
        if argument == "--" {
            let tail = arguments[at + 1..]
                .iter()
                .map(|value| (*value).to_owned())
                .collect();
            match command {
                CompilationCommand::Run => selected.run_args = tail,
                CompilationCommand::Test | CompilationCommand::Bench => selected.test_args = tail,
                CompilationCommand::Clippy => selected.lint_args = tail,
                _ => return Err(invalid("argument tails require run, test, bench or clippy")),
            }
            break;
        }
        if !argument.starts_with('-')
            && matches!(
                command,
                CompilationCommand::Test | CompilationCommand::Bench
            )
        {
            if selected.test_filter.replace(argument.to_owned()).is_some() {
                return Err(invalid("test or bench accepts only one name filter"));
            }
            at += 1;
            continue;
        }
        let (mut option, mut inline) = argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)));
        if inline.is_none()
            && (argument.starts_with("-p") || argument.starts_with("-F"))
            && argument.len() > 2
            && !argument.starts_with("--")
        {
            option = &argument[..2];
            inline = Some(&argument[2..]);
        }
        let flag = match option {
            "--workspace" => Some(&mut selected.workspace),
            "--all-features" => Some(&mut selected.all_features),
            "--no-default-features" => Some(&mut selected.no_default_features),
            "--lib" => Some(&mut selected.lib),
            "--bins" => Some(&mut selected.bins),
            "--tests" => Some(&mut selected.tests),
            "--examples" => Some(&mut selected.examples),
            "--benches" => Some(&mut selected.benches),
            "--all-targets" => Some(&mut selected.all_targets),
            "--release" | "-r" => Some(&mut selected.release),
            "--doc" => Some(&mut selected.doc),
            "--no-run" => Some(&mut selected.no_run),
            "--no-fail-fast" => Some(&mut selected.no_fail_fast),
            "--no-deps" => Some(&mut selected.no_deps),
            "--document-private-items" => Some(&mut selected.document_private_items),
            _ => None,
        };
        if let Some(flag) = flag {
            if inline.is_some() {
                return Err(invalid("boolean Cargo selectors do not take values"));
            }
            *flag = true;
        } else {
            if !matches!(
                option,
                "--package"
                    | "-p"
                    | "--exclude"
                    | "--features"
                    | "-F"
                    | "--bin"
                    | "--test"
                    | "--example"
                    | "--bench"
                    | "--target"
                    | "--profile"
            ) {
                return Err(invalid(
                    "unsupported Cargo selector; configure manifest, jobs and roots in the profile",
                ));
            }
            let value = if let Some(value) = inline {
                value
            } else {
                at += 1;
                arguments
                    .get(at)
                    .copied()
                    .ok_or_else(|| invalid("Cargo selector requires a value"))?
            }
            .to_owned();
            match option {
                "--package" | "-p" => selected.packages.push(value),
                "--exclude" => selected.exclude.push(value),
                "--features" | "-F" => selected.features.push(value),
                "--bin" => selected.bin.push(value),
                "--test" => selected.test.push(value),
                "--example" => selected.example.push(value),
                "--bench" => selected.bench.push(value),
                "--target" => selected.target.push(value),
                "--profile" => {
                    if selected.profile.replace(value).is_some() {
                        return Err(invalid("--profile may be selected only once"));
                    }
                }
                _ => return Err(invalid("unknown Cargo selector")),
            }
        }
        at += 1;
    }
    selected.cargo_arguments(command)?;
    selected.runtime_arguments(command)?;
    Ok((command, selected))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strings(arguments: &[&str]) -> io::Result<Invocation> {
        parse(&arguments.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn literal_run_tail_and_compact_selectors_are_preserved() {
        let Invocation::Run(options) = parse_strings(&[
            "--remote=p.json",
            "--stdin",
            "closed",
            "--",
            "run",
            "-ppkg",
            "-Fa,b",
            "--bin=app",
            "--",
            "",
            "--local",
            "a b",
            "α\nβ",
        ])
        .unwrap() else {
            panic!("expected invocation")
        };
        let (command, selection) = options.selected.unwrap();
        assert_eq!(command, CompilationCommand::Run);
        assert_eq!(selection.packages, ["pkg"]);
        assert_eq!(selection.features, ["a,b"]);
        assert_eq!(selection.bin, ["app"]);
        assert_eq!(selection.run_args, ["", "--local", "a b", "α\nβ"]);
    }

    #[test]
    fn absent_command_preserves_native_profile_intent() {
        let Invocation::Run(options) = parse_strings(&["--local", "p.json"]).unwrap() else {
            panic!("expected invocation")
        };
        assert!(options.selected.is_none());
        assert!(options.input.is_none());
    }

    #[test]
    fn ambiguous_authority_and_invalid_native_selections_are_refused() {
        for arguments in [
            vec!["--local", "p", "--remote", "q"],
            vec!["--remote", "p", "--stdin", "closed", "--stdin-file", "in"],
            vec!["--local", "p", "--rabsd", "one", "--rabsd", "two"],
            vec![
                "--local",
                "p",
                "build",
                "--manifest-path",
                "other/Cargo.toml",
            ],
            vec!["--local", "p", "build", "--profile", "dev", "--release"],
            vec!["--local", "p", "run", "--workspace"],
            vec!["--local", "p", "bench", "--release"],
            vec!["--local", "p", "check", "--", "--config", "x"],
            vec!["--local", "p", "clippy", "--", "--sysroot", "/other"],
        ] {
            assert!(parse_strings(&arguments).is_err(), "{arguments:?}");
        }
    }
}
