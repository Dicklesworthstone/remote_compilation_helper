//! Native selection and one-way handoff of Cargo operations.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod cargo_cache;
#[cfg(target_os = "linux")]
mod cargo_cli;
#[cfg(target_os = "linux")]
mod cargo_profile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod cargo_rch;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Run Cargo with native cache preparation, RCH, or a canonical profile.

Usage: rabs-cargo (--local PROFILE | --remote PROFILE) [OPTIONS] [--] [+TOOLCHAIN] [COMMAND ARGS...]
       rabs-cargo --rch [--] [CARGO ARGS...]
       rabs-cargo --cache [--] [CARGO ARGS...]

Options:
  --rch                  RCH remote execution with the worker-local RABS cache
  --cache                Local Cargo with bounded native RABS cache preparation
  --local PROFILE        Local canonical driver, optionally using its service_socket
  --remote PROFILE       Captured inputs and verified results over pinned TLS
  --rabsd EXECUTABLE     Explicit native driver (otherwise CARGO_RABS_DAEMON or sibling rabsd)
  --stdin closed|inherit  Supply EOF, or inherit nonterminal input for direct local run/test/bench
  --stdin-file RELATIVE  Capture one source-root-relative input file for run/test/bench execution
  -h, --help             Print help without starting any operation
  --version              Print version

RCH mode defaults to build and passes literal Cargo arguments, the selected
toolchain, stdin and inherited jobserver descriptors to RCH unchanged. It
requires Linux or macOS and a matching RCH installation, selected by
CARGO_RABS_RCH, a sibling rch, or PATH. RCH owns source receipts, admission,
execution and artifact return; remote execution is required and no local build
is started by this frontend. Worker-local cache preparation remains best effort.
RCH mode does not use canonical profiles or start a local RABS daemon.

Cache mode requires Linux and a matching rch-wkr, selected by CARGO_RABS_WORKER,
a sibling rch-wkr, or PATH. It runs CARGO (or cargo from PATH) with its original
arguments, cwd, stdin and jobserver descriptors; no arguments means build.
The native worker prepares or attaches to the local RABS daemon, then execs Cargo
once. Confirmed setup failure uses stock Cargo; uncertain cleanup runs no Cargo.
CARGO_RABS_WRAP and CARGO_RABS_DAEMON select installed local helpers. Existing
wrapper opt-outs remain respected. Explicit CARGO_RABS_ROOT_* admission uses the
matching rabs-cargo-root owner and cannot be bypassed by a cache setup failure.
Cache preparation and readiness do not guarantee a cache hit or change serving gates.

Canonical profile commands: check, build, clippy, doc, test, run, bench.
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
canonical operations; no local fallback or execution retry is performed.
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
    if arguments
        .first()
        .is_some_and(|argument| argument == "--rch")
    {
        if arguments.len() == 2 && (arguments[1] == "--help" || arguments[1] == "-h") {
            return write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let executable = std::env::current_exe()
                .map_err(|_| "frontend executable identity is unavailable".to_owned())?;
            return cargo_rch::run(&arguments[1..], &executable).map_err(|error| error.to_string());
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err("RCH remote dispatch requires Linux or macOS".into());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--cache")
    {
        if arguments.len() == 2 && (arguments[1] == "--help" || arguments[1] == "-h") {
            return write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into());
        }
        #[cfg(target_os = "linux")]
        {
            let executable = std::env::current_exe()
                .map_err(|_| "frontend executable identity is unavailable".to_owned())?;
            return cargo_cache::run(&arguments[1..], &executable)
                .map_err(|error| error.to_string());
        }
        #[cfg(not(target_os = "linux"))]
        return Err("native local cache preparation requires Linux".into());
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
