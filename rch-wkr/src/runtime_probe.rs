//! Fresh compile/link/execute evidence for recovery from an observed SIGILL.
//!
//! This permits a guarded retry of the worker. It does not diagnose the signal
//! or prove compatibility with the failed workload's toolchain, ISA or inputs.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::time::Instant;

const PROBE_BUDGET: Duration = Duration::from_secs(10);
const OUTPUT_LIMIT: usize = 16 * 1024;
const EXPECTED_OUTPUT: &str = "rch-runtime-probe-v1:500500\n";
const SOURCE: &str = r#"
fn main() {
    let count: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    assert_eq!(count, 1000);
    let values: Vec<u64> = (1..=count).collect();
    let sum: u64 = std::hint::black_box(values).into_iter().sum();
    assert_eq!(sum, 500500);
    println!("rch-runtime-probe-v1:{sum}");
}
"#;

#[derive(Debug, Serialize)]
struct RuntimeProbeReceipt {
    schema_version: u32,
    probe: &'static str,
    compiled: bool,
    executed: bool,
    output_verified: bool,
}

/// Keep the recovery probe independent of logging sinks and worker thread-pool
/// startup. Each invocation owns a new directory and a single process deadline;
/// neither an earlier executable nor a cached success receipt is reusable.
pub(crate) fn run(json: bool) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let receipt = runtime.block_on(probe(Path::new("rustc"), Instant::now() + PROBE_BUDGET))?;
    if json {
        println!("{}", serde_json::to_string(&receipt)?);
    } else {
        println!("Fresh Rust compile and execution succeeded; guarded retry is available.");
    }
    Ok(())
}

async fn probe(rustc: &Path, deadline: Instant) -> Result<RuntimeProbeReceipt> {
    ensure!(Instant::now() < deadline, "runtime probe deadline expired");
    let directory = tempfile::Builder::new()
        .prefix("rch-runtime-probe-")
        .tempdir()
        .context("create private runtime-probe directory")?;
    let source = directory.path().join("probe.rs");
    let executable = directory
        .path()
        .join(format!("probe{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&source, SOURCE).context("write fixed runtime-probe source")?;
    let output_budget = AtomicUsize::new(OUTPUT_LIMIT);

    // Use the worker's actual PATH and default installed toolchain. No Cargo
    // wrapper, downloaded toolchain or replacement compiler may stand in for a
    // broken installation. This intentionally makes no workload ISA claim.
    let mut compile = crate::executor::managed_command(rustc);
    compile
        .current_dir(directory.path())
        .env("RUSTUP_AUTO_INSTALL", "0")
        .args(["--crate-name", "rch_runtime_probe", "--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    crate::bounded_probe_command(compile, "runtime compile", deadline, &output_budget).await?;
    let metadata = std::fs::symlink_metadata(&executable)
        .context("runtime compiler did not produce an executable")?;
    ensure!(
        metadata.is_file(),
        "runtime compiler output is not a regular executable"
    );

    let mut execute = crate::executor::managed_command(&executable);
    execute.current_dir(directory.path()).arg("1000");
    let output =
        crate::bounded_probe_command(execute, "runtime execution", deadline, &output_budget)
            .await?;
    ensure!(
        output == EXPECTED_OUTPUT,
        "runtime execution did not return the exact fixture result"
    );
    ensure!(
        Instant::now() < deadline,
        "runtime probe deadline expired before verification"
    );
    Ok(RuntimeProbeReceipt {
        schema_version: 1,
        probe: "rust_compile_run",
        compiled: true,
        executed: true,
        output_verified: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_probe_compiles_and_executes_a_fresh_rust_program() {
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let receipt = probe(Path::new(&rustc), Instant::now() + PROBE_BUDGET)
            .await
            .expect("the installed Rust compiler must compile and run the fixture");
        assert_eq!(
            serde_json::to_value(receipt).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "probe": "rust_compile_run",
                "compiled": true,
                "executed": true,
                "output_verified": true,
            })
        );
    }

    #[tokio::test]
    async fn runtime_probe_never_uses_a_version_response_or_missing_compiler() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            probe(
                &directory.path().join("absent"),
                Instant::now() + PROBE_BUDGET
            )
            .await
            .is_err()
        );
        assert!(
            probe(Path::new("rustc"), Instant::now())
                .await
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
    }

    #[cfg(unix)]
    fn compiler_fixture(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_probe_requires_successful_compile_execution_and_exact_output() {
        let directory = tempfile::tempdir().unwrap();
        let compiler = directory.path().join("rustc");
        for (body, expected) in [
            ("exit 1", "runtime compile command exited"),
            ("printf 'rustc 1.100.0\\n'", "did not produce an executable"),
            (
                "printf '#!/bin/sh\\nexit 4\\n' > probe; chmod 700 probe",
                "runtime execution command exited",
            ),
            (
                "printf '#!/bin/sh\\necho wrong\\n' > probe; chmod 700 probe",
                "exact fixture result",
            ),
            ("ln -s /bin/true probe", "not a regular executable"),
        ] {
            compiler_fixture(&compiler, body);
            let error = probe(&compiler, Instant::now() + PROBE_BUDGET)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{body}: {error:#}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_probe_bounds_noisy_and_stalled_compilers() {
        let directory = tempfile::tempdir().unwrap();
        let compiler = directory.path().join("rustc");
        for (body, budget, expected) in [
            (
                "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",
                PROBE_BUDGET,
                "byte limit",
            ),
            ("sleep 30", Duration::from_millis(150), "timed out"),
        ] {
            compiler_fixture(&compiler, body);
            let error = tokio::time::timeout(
                Duration::from_secs(3),
                probe(&compiler, Instant::now() + budget),
            )
            .await
            .expect("owned probe processes must terminate promptly")
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }
}
