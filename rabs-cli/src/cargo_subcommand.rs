//! Cargo-discoverable native entrypoint over the existing RABS execution owners.
//!
//! Only launcher arguments are translated here. Cache preparation, RCH
//! admission, canonical execution and recovery retain their existing owners;
//! this frontend never starts a second Cargo command after handing off.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod cargo_cache;
#[cfg(target_os = "linux")]
mod cargo_cli;
#[cfg(target_os = "linux")]
mod cargo_profile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod cargo_rch;
#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod recovery;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Run Cargo through native RABS cache preparation or remote execution.

Usage: cargo rabs [OPTIONS] [--] [CARGO ARGS...]
       cargo rabs --rabs-canonical-local PROFILE [--] [COMMAND ARGS...]
       cargo rabs --rabs-canonical-remote PROFILE [--] [COMMAND ARGS...]
       cargo rabs --rabs-canonical PROFILE [--] [COMMAND ARGS...]
       cargo rabs --rabs-recover DIRECTORY [RECOVERY OPTIONS]

Options:
  --rabs-no-start        Attach only to an existing daemon; never start one
  --rabs-require-daemon  Refuse confirmed cache setup failure instead of stock Cargo
  --rabs-remote          RCH dispatch with worker-local RABS; remote execution required
  --rabs-canonical-local PROFILE   Existing native local canonical driver
  --rabs-canonical-remote PROFILE  Existing pinned-TLS canonical coordinator
  --rabs-canonical PROFILE         Existing direct-worker or daemon-owned pool driver
  --rabs-recover DIRECTORY         Resume/wait for retained results without recompiling
  -h, --help            Print help without starting any operation
  --version             Print version

Ordinary invocation defaults to build, preserving Cargo arguments, stdin,
toolchain selection, exit status, and inherited jobserver descriptors. Linux
cache preparation requires a matching rch-wkr, selected by CARGO_RABS_WORKER,
an installed sibling, or PATH. CARGO selects Cargo. CARGO_RABS_WRAP and
CARGO_RABS_DAEMON select the existing native cache helpers. Confirmed setup
failure permits stock Cargo unless --rabs-require-daemon was selected;
uncertain cleanup never starts Cargo. Explicit root admission remains mandatory.

Remote mode supports Linux/macOS and cannot combine with local daemon controls.
CARGO_RABS_RCH selects RCH. A remote outcome never starts a local retry.

Canonical/recovery modes must be the first and only launcher mode. They require
Linux and preserve the native profile, input, retained-result and authentication
checks. CARGO_RABS_DAEMON selects the native driver. Without an explicit Cargo
command, canonical local/remote select check and canonical worker selects build.
Use rabs-cargo when the profile's saved command/selection should be retained.

Recovery defaults to the saved direct delivery or the same daemon job's wait.
Select --status, --cancel, --resume-to NEW, --delivery EXISTING, or
--acknowledge EXISTING explicitly as needed; --prefix-from OLD requires
--resume-to. Older direct records require --canonical-state-dir ORIGINAL.
Recovery never submits another build, recaptures inputs or authorizes publication.
";

#[derive(Debug, PartialEq, Eq)]
enum Invocation<'a> {
    Help,
    Cache {
        arguments: &'a [OsString],
        no_start: bool,
        require_daemon: bool,
    },
    Remote(&'a [OsString]),
    Canonical(Vec<OsString>),
    Recover(&'a [OsString]),
}

fn parse(arguments: &[OsString]) -> Result<Invocation<'_>, &'static str> {
    if let Some(mode) = arguments
        .first()
        .and_then(|argument| match argument.to_str() {
            Some("--rabs-canonical-local") => Some(("--local", "check")),
            Some("--rabs-canonical-remote") => Some(("--remote", "check")),
            Some("--rabs-canonical") => Some(("--worker", "build")),
            _ => None,
        })
    {
        let profile = arguments
            .get(1)
            .filter(|value| !value.is_empty() && !value.as_encoded_bytes().starts_with(b"-"))
            .ok_or("canonical mode requires a profile path")?;
        let cargo = arguments[2..]
            .strip_prefix(&[OsString::from("--")])
            .unwrap_or(&arguments[2..]);
        let mut translated = vec![mode.0.into(), profile.clone(), "--".into()];
        if cargo.is_empty() {
            translated.push(mode.1.into());
        } else {
            translated.extend_from_slice(cargo);
        }
        return Ok(Invocation::Canonical(translated));
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--rabs-recover")
    {
        return Ok(Invocation::Recover(&arguments[1..]));
    }
    let mut no_start = false;
    let mut require_daemon = false;
    let mut remote = false;
    let mut remaining = arguments;
    while let Some(argument) = remaining.first() {
        match argument.to_str() {
            Some("--") => {
                remaining = &remaining[1..];
                break;
            }
            Some("--help" | "-h") => return Ok(Invocation::Help),
            Some("--rabs-no-start") => no_start = true,
            Some("--rabs-require-daemon") => require_daemon = true,
            Some("--rabs-remote") => remote = true,
            _ if argument.as_encoded_bytes().starts_with(b"--rabs-") => {
                return Err("unknown launcher control or canonical/recovery mode was not first");
            }
            _ => break,
        }
        remaining = &remaining[1..];
    }
    if remote {
        if no_start || require_daemon {
            return Err("remote dispatch cannot combine with local-daemon controls");
        }
        Ok(Invocation::Remote(remaining))
    } else {
        Ok(Invocation::Cache {
            arguments: remaining,
            no_start,
            require_daemon,
        })
    }
}

fn run(arguments: &[OsString]) -> Result<(), String> {
    // Rustup discovery reexecutes this exact native image. Handle that private
    // owner before Cargo's public subcommand grammar, as rabs-cargo does.
    #[cfg(target_os = "linux")]
    if let Some(result) = cargo_profile::run_rustup_guard(arguments) {
        return result.map_err(|error| error.to_string());
    }
    let arguments = arguments
        .strip_prefix(&[OsString::from("rabs")])
        .unwrap_or(arguments);
    if let Some(info) =
        rabs_protocol::release_authorization::build_info_for_args("cargo-rabs", arguments)
    {
        return writeln!(io::stdout().lock(), "{info}").map_err(|error| error.to_string());
    }
    if arguments == [OsString::from("--version")] {
        return writeln!(
            io::stdout().lock(),
            "cargo-rabs {}",
            env!("CARGO_PKG_VERSION")
        )
        .map_err(|error| error.to_string());
    }
    match parse(arguments).map_err(str::to_owned)? {
        Invocation::Help => {
            write!(io::stdout().lock(), "{HELP}").map_err(|error| error.to_string())
        }
        Invocation::Cache {
            arguments,
            no_start,
            require_daemon,
        } => {
            #[cfg(target_os = "linux")]
            {
                let executable = std::env::current_exe().map_err(|error| error.to_string())?;
                cargo_cache::run(
                    arguments,
                    &executable,
                    cargo_cache::Policy {
                        no_start,
                        require_daemon,
                    },
                )
                .map_err(|error| error.to_string())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (arguments, no_start, require_daemon);
                Err("native local cache preparation requires Linux".into())
            }
        }
        Invocation::Remote(arguments) => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let executable = std::env::current_exe().map_err(|error| error.to_string())?;
                cargo_rch::run(arguments, &executable).map_err(|error| error.to_string())
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = arguments;
                Err("RCH remote dispatch requires Linux or macOS".into())
            }
        }
        Invocation::Canonical(arguments) => {
            // Canonical selectors have their own literal program delimiter;
            // no second frontend mode may reach their Cargo selector parser.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            cargo_rch::reject_frontend_controls(&arguments[3..])
                .map_err(|error| error.to_string())?;
            #[cfg(target_os = "linux")]
            {
                match cargo_cli::parse(&arguments).map_err(|error| error.to_string())? {
                    cargo_cli::Invocation::Help => {
                        write!(io::stdout().lock(), "{HELP}").map_err(|error| error.to_string())
                    }
                    cargo_cli::Invocation::Run(options) => {
                        let executable =
                            std::env::current_exe().map_err(|error| error.to_string())?;
                        cargo_profile::run(&options, &executable).map_err(|error| error.to_string())
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = arguments;
                Err("canonical Cargo operations require Linux".into())
            }
        }
        Invocation::Recover(arguments) => {
            #[cfg(target_os = "linux")]
            {
                match cli::parse(arguments).map_err(str::to_owned)? {
                    cli::Invocation::Help => {
                        write!(io::stdout().lock(), "{HELP}").map_err(|error| error.to_string())
                    }
                    cli::Invocation::Recover(mut options) => {
                        options.resume_current = options.job_control.is_none()
                            && options.resume_to.is_none()
                            && options.acknowledge.is_none();
                        let executable =
                            std::env::current_exe().map_err(|error| error.to_string())?;
                        recovery::run(&options, &executable).map_err(|error| error.to_string())
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = arguments;
                Err("retained RABS recovery requires Linux".into())
            }
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "cargo-rabs: refused: {error}; no execution retry"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn canonical_aliases_keep_their_original_default_commands() {
        for (alias, native, command) in [
            ("--rabs-canonical-local", "--local", "check"),
            ("--rabs-canonical-remote", "--remote", "check"),
            ("--rabs-canonical", "--worker", "build"),
        ] {
            for trailing in [vec![], vec!["--"]] {
                let mut input = arguments(&[alias, "profile.json"]);
                input.extend(arguments(&trailing));
                assert_eq!(
                    parse(&input).unwrap(),
                    Invocation::Canonical(arguments(&[native, "profile.json", "--", command,]))
                );
            }
        }
    }

    #[test]
    fn public_mode_controls_remain_exclusive_and_bounded() {
        for input in [
            vec!["--rabs-no-start", "--rabs-remote", "check"],
            vec!["--rabs-remote", "--rabs-require-daemon", "check"],
            vec!["--rabs-no-start", "--rabs-canonical-local", "p.json"],
            vec!["--rabs-no-start", "--rabs-recover", "retained"],
            vec!["--rabs-canonical"],
            vec!["--rabs-canonical-remote", "--"],
            vec!["--rabs-unknown"],
        ] {
            assert!(parse(&arguments(&input)).is_err(), "{input:?}");
        }
    }

    #[test]
    fn launcher_delimiter_is_consumed_once_and_later_arguments_are_literal() {
        for input in [
            arguments(&["--", "--rabs-remote"]),
            arguments(&["--", "--", "--rabs-recover"]),
            arguments(&["--", "test", "--", "--rabs-no-start", ""]),
        ] {
            assert_eq!(
                parse(&input).unwrap(),
                Invocation::Cache {
                    arguments: &input[1..],
                    no_start: false,
                    require_daemon: false,
                }
            );
        }
        let input = arguments(&[
            "--rabs-no-start",
            "--rabs-require-daemon",
            "test",
            "--",
            "--rabs-remote",
        ]);
        assert_eq!(
            parse(&input).unwrap(),
            Invocation::Cache {
                arguments: &input[2..],
                no_start: true,
                require_daemon: true,
            }
        );
    }
}
