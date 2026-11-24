//! Exact operator options and bounded native Cargo selectors.

use rabs_sandbox::cargo_check::{CompilationCommand, CompilationSelection, CompilationStdin};
use std::ffi::OsString;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Local,
    Remote,
    Worker,
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
    pub toolchain: Option<String>,
    pub selected: Option<(CompilationCommand, CompilationSelection)>,
}

pub(crate) enum Invocation {
    Help,
    Run(Box<Options>),
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

pub(crate) fn valid_toolchain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.starts_with(['+', '-'])
        && !name
            .chars()
            .any(|value| value.is_whitespace() || value.is_control())
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
            Some("--local" | "--remote" | "--worker" | "--rabsd" | "--stdin" | "--stdin-file")
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
            Some("--local" | "--remote" | "--worker") => {
                if mode.is_some() {
                    return Err(invalid(
                        "select exactly one local, remote or worker profile",
                    ));
                }
                mode = Some(if name == "--local" {
                    Mode::Local
                } else if name == "--worker" {
                    Mode::Worker
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
    let mode = mode.ok_or_else(|| invalid("select --local, --remote or --worker PROFILE"))?;
    let profile = profile.ok_or_else(|| invalid("profile path is missing"))?;
    let toolchain = if arguments
        .get(at)
        .is_some_and(|argument| argument.as_encoded_bytes().starts_with(b"+"))
    {
        let selector = arguments[at]
            .to_str()
            .ok_or_else(|| invalid("Rustup toolchain selector must be UTF-8"))?;
        let name = &selector[1..];
        if !valid_toolchain_name(name) || at + 1 == arguments.len() {
            return Err(invalid(
                "+toolchain requires one bounded literal selector before a Cargo command",
            ));
        }
        at += 1;
        Some(name.to_owned())
    } else {
        None
    };
    let selected = if at == arguments.len() {
        None
    } else {
        Some(selection(&arguments[at..])?)
    };
    if mode == Mode::Worker && selected.is_none() {
        return Err(invalid("worker profiles require an explicit Cargo command"));
    }
    Ok(Invocation::Run(Box::new(Options {
        mode,
        profile,
        daemon,
        input,
        toolchain,
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
        "nextest" if arguments.get(1) == Some(&"run") => CompilationCommand::Nextest,
        "nextest" => return Err(invalid("canonical nextest requires the run subcommand")),
        "run" => CompilationCommand::Run,
        "bench" => CompilationCommand::Bench,
        _ => return Err(invalid("unsupported canonical Cargo command")),
    };
    let mut selected = CompilationSelection::default();
    let mut at = if command == CompilationCommand::Nextest {
        2
    } else {
        1
    };
    while at < arguments.len() {
        let argument = arguments[at];
        if argument == "--" {
            let tail = arguments[at + 1..]
                .iter()
                .map(|value| (*value).to_owned())
                .collect();
            match command {
                CompilationCommand::Run => selected.run_args = tail,
                CompilationCommand::Test
                | CompilationCommand::Bench
                | CompilationCommand::Nextest => {
                    selected.test_args = tail;
                }
                CompilationCommand::Clippy => selected.lint_args = tail,
                _ => {
                    return Err(invalid(
                        "argument tails require run, test, nextest, bench or clippy",
                    ));
                }
            }
            break;
        }
        if !argument.starts_with('-')
            && matches!(
                command,
                CompilationCommand::Test | CompilationCommand::Bench | CompilationCommand::Nextest
            )
        {
            if selected.test_filter.replace(argument.to_owned()).is_some() {
                return Err(invalid(
                    "canonical test, nextest or bench accepts only one name filter",
                ));
            }
            at += 1;
            continue;
        }
        let (mut option, mut inline) = argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)));
        if inline.is_none()
            && (argument.starts_with("-p")
                || argument.starts_with("-F")
                || (command == CompilationCommand::Nextest
                    && (argument.starts_with("-E") || argument.starts_with("-j"))))
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
                    | "--cargo-profile"
                    | "--test-threads"
                    | "--jobs"
                    | "-j"
                    | "--filterset"
                    | "-E"
                    | "--retries"
                    | "--run-ignored"
                    | "--partition"
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
                "--profile" if command == CompilationCommand::Nextest => {
                    if selected.runner_profile.replace(value).is_some() {
                        return Err(invalid("nextest --profile may be selected only once"));
                    }
                }
                "--profile" | "--cargo-profile" => {
                    if option == "--cargo-profile" && command != CompilationCommand::Nextest {
                        return Err(invalid("--cargo-profile requires nextest run"));
                    }
                    if selected.profile.replace(value).is_some() {
                        return Err(invalid(
                            "Cargo compilation profile may be selected only once",
                        ));
                    }
                }
                "--test-threads" | "--jobs" | "-j" if command == CompilationCommand::Nextest => {
                    let count = value
                        .parse::<u32>()
                        .ok()
                        .filter(|count| (1..=4096).contains(count) && count.to_string() == value)
                        .ok_or_else(|| {
                            invalid("nextest test threads must be an integer between 1 and 4096")
                        })?;
                    if selected.test_threads.replace(count).is_some() {
                        return Err(invalid("nextest test threads may be selected only once"));
                    }
                }
                "--retries" if command == CompilationCommand::Nextest => {
                    let count = value
                        .parse::<u32>()
                        .map_err(|_| invalid("nextest --retries requires a nonnegative integer"))?;
                    if selected.retries.replace(count).is_some() {
                        return Err(invalid("nextest --retries may be selected only once"));
                    }
                }
                "--run-ignored" if command == CompilationCommand::Nextest => {
                    if selected.run_ignored.replace(value).is_some() {
                        return Err(invalid("nextest --run-ignored may be selected only once"));
                    }
                }
                "--partition" if command == CompilationCommand::Nextest => {
                    if selected.partition.replace(value).is_some() {
                        return Err(invalid("nextest --partition may be selected only once"));
                    }
                }
                "--filterset" | "-E" if command == CompilationCommand::Nextest => {
                    selected.filtersets.push(value);
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
    fn nextest_keeps_compile_and_runner_selection_distinct() {
        let Invocation::Run(options) = parse_strings(&[
            "--remote",
            "p.json",
            "nextest",
            "run",
            "--workspace",
            "--cargo-profile=release",
            "--profile",
            "ci",
            "-Epackage(core)",
            "--filterset",
            "test(roundtrip)",
            "-j1",
            "roundtrip",
            "--",
            "--exact",
        ])
        .unwrap() else {
            panic!("expected invocation");
        };
        let (command, selected) = options.selected.unwrap();
        assert_eq!(command, CompilationCommand::Nextest);
        assert_eq!(selected.profile.as_deref(), Some("release"));
        assert_eq!(selected.runner_profile.as_deref(), Some("ci"));
        assert_eq!(selected.test_threads, Some(1));
        assert_eq!(selected.filtersets, ["package(core)", "test(roundtrip)"]);
        assert_eq!(selected.test_filter.as_deref(), Some("roundtrip"));
        assert_eq!(selected.test_args, ["--exact"]);
        let build = selected
            .nextest_build_selection()
            .unwrap()
            .cargo_arguments(CompilationCommand::Test)
            .unwrap();
        assert_eq!(
            build,
            ["test", "--workspace", "--no-run", "--profile", "release"]
        );
        assert_eq!(
            selected.runtime_arguments(command).unwrap(),
            ["--", "--exact"]
        );
    }

    #[test]
    fn nextest_partitions_reach_every_canonical_mode_as_literal_runner_selection() {
        for mode in ["--local", "--remote", "--worker"] {
            for partition in ["hash:1/4", "slice:2/4", "count:4/4"] {
                for inline in [false, true] {
                    let option = format!("--partition={partition}");
                    let mut arguments = vec![mode, "p.json", "nextest", "run"];
                    if inline {
                        arguments.push(&option);
                    } else {
                        arguments.extend(["--partition", partition]);
                    }
                    arguments.extend(["--test-threads", "2", "-Eall()", "--", "--exact"]);
                    let Invocation::Run(options) = parse_strings(&arguments).unwrap() else {
                        panic!("expected nextest invocation");
                    };
                    let (command, selected) = options.selected.unwrap();
                    assert_eq!(command, CompilationCommand::Nextest);
                    assert_eq!(selected.partition.as_deref(), Some(partition));
                    assert_eq!(selected.test_threads, Some(2));
                    assert_eq!(selected.filtersets, ["all()"]);
                    assert_eq!(selected.test_args, ["--exact"]);
                    assert_eq!(
                        selected
                            .nextest_build_selection()
                            .unwrap()
                            .cargo_arguments(CompilationCommand::Test)
                            .unwrap(),
                        ["test", "--no-run"]
                    );
                }
            }
        }
        for options in [
            vec!["--partition"],
            vec!["--partition="],
            vec!["--partition", "hash:0/4"],
            vec!["--partition", "slice:5/4"],
            vec!["--partition", "count:1/0"],
            vec!["--partition", "hash:1/4", "--partition=slice:2/4"],
        ] {
            let mut arguments = vec!["--local", "p.json", "nextest", "run"];
            arguments.extend(options);
            assert!(parse_strings(&arguments).is_err(), "{arguments:?}");
        }
        for command in ["build", "check", "test", "run", "bench", "doc", "clippy"] {
            assert!(
                parse_strings(&["--remote", "p.json", command, "--partition=hash:1/4"]).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn nextest_accepts_explicit_retry_and_ignored_test_controls() {
        for mode in ["--local", "--remote", "--worker"] {
            for ignored in ["default", "only", "all"] {
                let Invocation::Run(options) = parse_strings(&[
                    mode,
                    "p.json",
                    "nextest",
                    "run",
                    "--run-ignored",
                    ignored,
                    "--retries=0",
                ])
                .unwrap() else {
                    panic!("expected nextest invocation");
                };
                let (command, selection) = options.selected.unwrap();
                assert_eq!(selection.run_ignored.as_deref(), Some(ignored));
                assert_eq!(selection.retries, Some(0));
                assert_eq!(
                    selection.cargo_arguments(command).unwrap(),
                    ["nextest", "run", "--retries", "0", "--run-ignored", ignored]
                );
            }
        }
        for arguments in [
            vec!["nextest", "run", "--retries"],
            vec!["nextest", "run", "--retries=-1"],
            vec!["nextest", "run", "--retries=4294967296"],
            vec!["nextest", "run", "--retries=1", "--retries", "2"],
            vec!["nextest", "run", "--run-ignored=unknown"],
            vec!["nextest", "run", "--run-ignored=only", "--run-ignored=all"],
            vec!["test", "--run-ignored=only"],
            vec!["build", "--retries=1"],
        ] {
            let mut invocation = vec!["--local", "p.json"];
            invocation.extend(arguments);
            assert!(parse_strings(&invocation).is_err(), "{invocation:?}");
        }
    }

    #[test]
    fn nextest_refuses_unimplemented_commands_and_ambiguous_controls() {
        for arguments in [
            vec!["--local", "p", "nextest"],
            vec!["--local", "p", "nextest", "list"],
            vec!["--local", "p", "nextest", "run", "--doc"],
            vec!["--local", "p", "nextest", "run", "--build-jobs", "2"],
            vec!["--local", "p", "nextest", "run", "--message-format", "json"],
            vec![
                "--local",
                "p",
                "nextest",
                "run",
                "--profile",
                "ci",
                "--profile",
                "default",
            ],
            vec!["--local", "p", "nextest", "run", "-j1", "--jobs", "2"],
            vec!["--local", "p", "nextest", "run", "--test-threads", "0"],
            vec![
                "--local",
                "p",
                "nextest",
                "run",
                "--test-threads",
                "num-cpus",
            ],
            vec!["--local", "p", "test", "--cargo-profile", "release"],
            vec!["--local", "p", "test", "--filterset", "all()"],
            vec!["--local", "p", "build", "--test-threads", "1"],
        ] {
            assert!(parse_strings(&arguments).is_err(), "{arguments:?}");
        }
        for mode in ["--local", "--remote", "--worker"] {
            let Invocation::Run(options) = parse_strings(&[mode, "p", "nextest", "run"]).unwrap()
            else {
                panic!("expected invocation");
            };
            assert_eq!(options.selected.unwrap().1.test_threads, None);
        }
    }

    #[test]
    fn absent_command_preserves_native_profile_intent() {
        let Invocation::Run(options) = parse_strings(&["--local", "p.json"]).unwrap() else {
            panic!("expected invocation")
        };
        assert!(options.selected.is_none());
        assert!(options.input.is_none());
        assert!(options.toolchain.is_none());
    }

    #[test]
    fn leading_toolchain_selection_does_not_interpret_program_arguments() {
        for separator in [false, true] {
            let mut arguments = vec!["--local", "p.json"];
            if separator {
                arguments.push("--");
            }
            arguments.extend([
                "+nightly-2026-08-31",
                "run",
                "--",
                "+literal",
                "--toolchain",
            ]);
            let Invocation::Run(options) = parse_strings(&arguments).unwrap() else {
                panic!("expected invocation")
            };
            assert_eq!(options.toolchain.as_deref(), Some("nightly-2026-08-31"));
            let (command, selection) = options.selected.unwrap();
            assert_eq!(command, CompilationCommand::Run);
            assert_eq!(selection.run_args, ["+literal", "--toolchain"]);
        }
        for selector in [
            "+",
            "++nightly",
            "+-nightly",
            "+night ly",
            "+nightly\n",
            "+nightly\u{85}",
        ] {
            assert!(parse_strings(&["--local", "p", selector, "build"]).is_err());
        }
        assert!(parse_strings(&["--local", "p", "+nightly"]).is_err());
        assert!(parse_strings(&["--local", "p", "+one", "+two", "build"]).is_err());
        assert!(
            parse_strings(&["--local", "p", &format!("+{}", "a".repeat(1025)), "build"]).is_err()
        );
        use std::os::unix::ffi::OsStringExt;
        assert!(
            parse(&[
                "--local".into(),
                "p".into(),
                OsString::from_vec(b"+nightly\xff".to_vec()),
                "build".into(),
            ])
            .is_err()
        );
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
