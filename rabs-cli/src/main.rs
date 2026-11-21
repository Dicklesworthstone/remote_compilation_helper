//! Native recovery of retained dependency and canonical Cargo results.
//!
//! This operator reads intent, never authorizes execution or publication. The
//! existing rabsd owner remains responsible for pinned authentication,
//! durable job control, result verification, bounded retrieval, and acknowledgment.

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
daemon or worker or verifying outputs. An explicit operation hands off once to
the existing native rabsd owner. It never authorizes an execution retry, compiler
skip, or publication. Keep the recovery and admission directories exclusively
owned while operating. Linux is required for recovery operations.

Arguments:
  DIRECTORY                         Retained result-* or canonical operation directory

Options:
  --wait                             Wait for/replay a daemon job's verified result
  --status                           Inspect the same daemon job without waiting
  --cancel                           Request cancellation from that job's owner
  --resume-to NEW_DIRECTORY           Retrieve results into a new directory
  --delivery DELIVERY_DIRECTORY      Reconcile a daemon job's retained local delivery
  --acknowledge DELIVERY_DIRECTORY    Verify and acknowledge an existing delivery
  --no-prefix                        Download afresh; preserve previous partial files
  --prefix-from OLD_DIRECTORY         Use another interrupted delivery as untrusted hints
  --rabsd EXECUTABLE                  Native daemon; never selected from retained metadata
  --canonical-state-dir DIRECTORY    ORIGINAL admission state for older canonical records
  -h, --help                         Print help
  --version                          Print version

Select at most one job control or result destination. Daemon jobs are recognized
from their retained operation.json and keep their saved socket and job ID. No
original source, toolchain or bundle is needed. Inspection also works offline;
active controls require the existing private daemon socket. --wait preserves a
recorded live-stderr preference and returns the compiler result. Other controls
return native job-control status, not compiler success or proof of cleanup.
The daemon owns TLS and result verification; client TLS credentials are not
required. Job resume uses only an explicit --prefix-from, otherwise a fresh
receiver. Lost replies never cause another submission or execution.

Direct canonical recovery requires bundle/request.json, never spec.json. Older
direct operations require their original --canonical-state-dir; current
environment defaults cannot replace that history. Direct resume and
acknowledgment require RABS_COORD_TLS_CA, RABS_COORD_TLS_CERT, and
RABS_COORD_TLS_KEY explicitly. Their default partial-delivery prefix behavior
is unchanged; --no-prefix downloads afresh.
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
