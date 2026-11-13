//! Native recovery of retained dependency and canonical Cargo results.
//!
//! This operator reads intent, never authorizes execution or publication. The
//! existing rabsd transport remains responsible for pinned authentication,
//! result verification, bounded retrieval, and acknowledgment.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod recovery;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Recover retained dependency or canonical Cargo results without recompiling.

Usage: rabs-recover [OPTIONS] DIRECTORY

With no operation flag, inspect private intent metadata without contacting a
worker or verifying outputs. Resume and acknowledgment hand off once to the
existing pinned TLS rabsd operator. They never authorize an execution retry,
compiler skip, or publication. Keep the recovery and admission directories
exclusively owned while operating. Linux is required for recovery operations.

Arguments:
  DIRECTORY                         Retained result-* or canonical operation directory

Options:
  --resume-to NEW_DIRECTORY           Retrieve results into a new directory
  --acknowledge DELIVERY_DIRECTORY    Verify and acknowledge an existing delivery
  --no-prefix                        Download afresh; preserve previous partial files
  --prefix-from OLD_DIRECTORY         Use another interrupted delivery as untrusted hints
  --rabsd EXECUTABLE                  Native daemon; never selected from retained metadata
  --canonical-state-dir DIRECTORY    ORIGINAL admission state for older canonical records
  -h, --help                         Print help
  --version                          Print version

Canonical recovery requires bundle/request.json, never spec.json. Older
operations require their original --canonical-state-dir; current environment
defaults cannot replace that history. Resume and acknowledgment require
RABS_COORD_TLS_CA, RABS_COORD_TLS_CERT, and RABS_COORD_TLS_KEY explicitly.
";

fn run(arguments: &[OsString]) -> Result<(), String> {
    if let Some(info) =
        rabs_protocol::release_authorization::build_info_for_args("rabs-recover", arguments)
    {
        return writeln!(io::stdout().lock(), "{info}").map_err(|_| "output unavailable".into());
    }
    if arguments == [OsString::from("--version")] {
        return writeln!(
            io::stdout().lock(),
            "rabs-recover {}",
            env!("CARGO_PKG_VERSION")
        )
        .map_err(|_| "output unavailable".into());
    }
    #[cfg(target_os = "linux")]
    {
        match cli::parse(arguments).map_err(str::to_owned)? {
            cli::Invocation::Help => {
                write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into())
            }
            cli::Invocation::Recover(options) => {
                // Resolve the installed generation before reading any intent.
                // A concurrent activation must not select another sibling rabsd.
                let executable = std::env::current_exe()
                    .map_err(|_| "recovery executable identity is unavailable".to_owned())?;
                recovery::run(&options, &executable).map_err(|error| error.to_string())
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
            return write!(io::stdout().lock(), "{HELP}").map_err(|_| "output unavailable".into());
        }
        Err("live RABS recovery currently requires Linux".into())
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "rabs-recover: refused: {error}; no execution retry"
            );
            ExitCode::from(2)
        }
    }
}
