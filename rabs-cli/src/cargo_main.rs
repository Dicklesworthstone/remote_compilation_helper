//! Native selection and one-way handoff of canonical Cargo operations.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod cargo_cli;
#[cfg(target_os = "linux")]
mod cargo_profile;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Run an explicitly configured canonical Cargo operation.

Usage: rabs-cargo (--local PROFILE | --remote PROFILE) [OPTIONS] [--] [+TOOLCHAIN] [COMMAND ARGS...]

Options:
  --local PROFILE        Local canonical driver, optionally using its service_socket
  --remote PROFILE       Captured inputs and verified results over pinned TLS
  --rabsd EXECUTABLE     Explicit native driver (otherwise CARGO_RABS_DAEMON or sibling rabsd)
  --stdin closed|inherit  Supply EOF, or inherit nonterminal input for direct local run/test/bench
  --stdin-file RELATIVE  Capture one source-root-relative input file for run/test/bench execution
  -h, --help             Print help without starting any operation
  --version              Print version

Commands: check, build, clippy, doc, test, run, bench.
Package, workspace, feature, target and profile selectors follow the command.
Literal program/test/lint arguments follow its -- separator. Manifest, jobs,
environment and physical roots remain explicit profile settings. With no
command, retain the profile's command and selection. An explicit command
replaces both, including an empty selection for ordinary Cargo defaults.

Profiles select toolchain_root or toolchain: rustup. A leading +TOOLCHAIN requires
the Rustup profile and a Cargo command. Discovery honors the caller's directory
and environment, never installs a toolchain, and retains only its physical root.
CARGO_RABS_RUSTUP can select the discovery executable instead of PATH.
Remote profiles may use output_root
for a fresh output destination per invocation, or one absent output_destination.
Run and executing bench through a service require explicit closed stdin or a
captured stdin_file. Test defaults to EOF and can explicitly select input when
executing its targets. Runtime outcomes are never cached. Linux is required for
operations; no local fallback or execution retry is performed.
";

fn run(arguments: &[OsString]) -> Result<(), String> {
    if let Some(info) =
        rabs_protocol::release_authorization::build_info_for_args("rabs-cargo", arguments)
    {
        return writeln!(io::stdout().lock(), "{info}").map_err(|_| "output unavailable".into());
    }
    if arguments == [OsString::from("--version")] {
        return writeln!(
            io::stdout().lock(),
            "rabs-cargo {}",
            env!("CARGO_PKG_VERSION")
        )
        .map_err(|_| "output unavailable".into());
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(result) = cargo_profile::run_rustup_guard(arguments) {
            return result.map_err(|error| error.to_string());
        }
        match cargo_cli::parse(arguments).map_err(|error| error.to_string())? {
            cargo_cli::Invocation::Help => {
                write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into())
            }
            cargo_cli::Invocation::Run(options) => {
                let executable = std::env::current_exe()
                    .map_err(|_| "frontend executable identity is unavailable".to_owned())?;
                cargo_profile::run(&options, &executable).map_err(|error| error.to_string())
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
            return write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into());
        }
        Err("canonical Cargo operations currently require Linux".into())
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "rabs-cargo: refused: {error}; no execution retry"
            );
            ExitCode::from(2)
        }
    }
}
