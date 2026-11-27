//! Optional Linux procfs reader for a non-root worker's checked GC snapshot.
//! A capability-bearing installation must expose only this fixed operation.

#[cfg(target_os = "linux")]
#[path = "control_capture/proc_references.rs"]
mod proc_references;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    if std::env::args_os().len() == 1 {
        return match proc_references::capture() {
            Ok(0) => std::process::ExitCode::SUCCESS,
            Ok(_) => std::process::ExitCode::from(125),
            Err(error) => {
                eprintln!("RCH_GC_CENSUS_REFUSED: {error}");
                std::process::ExitCode::from(125)
            }
        };
    }

    eprintln!("rch-gc-proc-references requires Linux and accepts no arguments");
    std::process::ExitCode::from(125)
}
