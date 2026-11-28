//! Native, local installation and verification of complete RABS generations.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod installer;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Install, package, or inspect a complete, trusted RABS toolset on Linux.

Usage: rabs-install (--from-build DIR | --from-bundle DIR | --from-archive TAR_GZ)
                    [--bin-dir ABSOLUTE_DIRECTORY] [--probe | --verify]
       rabs-install (--from-build DIR | --from-bundle DIR)
                    --package TAR_GZ --target TARGET
                    [--require-source FULL_COMMIT]
       rabs-install --probe-installed [--bin-dir ABSOLUTE_DIRECTORY]

Options:
  --from-build DIR      Split wrapper-release and daemon-release output directory
  --from-bundle DIR     Extracted, authenticated release bundle
  --from-archive FILE   Authenticated flat gzip release archive
  --package FILE        Produce and self-verify a deterministic flat release archive
  --target TARGET       Target triple for --package (x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu)
  --require-source SHA  Verify all 9 native --rabs-build-info stamps match this 40-hex commit
  --bin-dir DIR         Destination; defaults to $HOME/.local/bin
  --probe               Check staged launchers before atomic activation
  --verify              Read-only comparison against the selected trusted bytes
  --probe-installed     Validate and launch-check the active managed generation
  --version             Print version
  -h, --help            Print help

Verify publisher signatures/checksums before supplying a bundle or archive.
Content hashes detect corruption; they do not authenticate a publisher.
All nine native tools, including rabs-install, activate together.
Existing generations and failed installation stages are retained. Unmanaged
entries are never replaced. No service is started and no Cargo configuration
is changed. --verify never executes installed tools.
Launch checks have a ten-second deadline per tool and clean up their owned
process groups. Retained SSH images and fleet --ssh transport are not
implemented by this local installer; unsupported options fail explicitly.
";

fn run(arguments: &[OsString]) -> Result<bool, String> {
    if let Some(info) =
        rabs_protocol::release_authorization::build_info_for_args("rabs-install", arguments)
    {
        writeln!(io::stdout().lock(), "{info}").map_err(|error| error.to_string())?;
        return Ok(true);
    }
    if arguments == [OsString::from("--version")] {
        println!("rabs-install {}", env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
        print!("{HELP}");
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        let (receipt, success) = installer::run(arguments).map_err(|error| error.to_string())?;
        serde_json::to_writer(io::stdout().lock(), &receipt).map_err(|error| error.to_string())?;
        println!();
        Ok(success)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("native RABS installation requires Linux".into())
    }
}

fn main() -> ExitCode {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("rabs-install: {error}");
            ExitCode::FAILURE
        }
    }
}
