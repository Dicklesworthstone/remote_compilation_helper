//! `rabs-replay` CLI binary (W2/B013).
//!
//! Runs corpus inspection, B010 stratification, and paired interleaved
//! stock-vs-candidate benchmarks directly over B002 NDJSONL traces.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match rabs_replay::cli::run_from_args(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rabs-replay: {error}");
            ExitCode::from(2)
        }
    }
}
