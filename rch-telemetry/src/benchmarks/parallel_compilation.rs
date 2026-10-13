//! Paired serial/parallel rustc throughput benchmark (bd-uerk9).
//!
//! Compile the SAME fixed dependency-free crate graph twice, into fresh private
//! outputs. The second pass has an explicit, bounded compiler pool. Both use
//! one codegen unit per compiler; CPU count is a concurrency limit, never a
//! multiplier applied to measured throughput. Every output must exist and the
//! two passes must produce identical bytes before a measurement is returned.
//!
//! This measures a small rlib graph, not a full Cargo build, link, incremental
//! build, or an estimate of unrestricted whole-machine capacity. The default
//! pool is capped at 16 compilers. Callers must still arrange idle/admitted
//! execution; this module does not reserve fleet slots.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use super::CompilationBenchmarkError;

/// Change whenever the source, crate graph or compiler options change.
pub const PARALLEL_COMPILATION_WORKLOAD_VERSION: u32 = 1;
/// Fixed work across all machines: 32 independent libraries plus their consumer.
pub const PARALLEL_COMPILATION_CRATES: u32 = 33;
/// Bound optional benchmark resource use, even on very large workers.
pub const MAX_PARALLEL_COMPILERS: usize = 16;
const MAX_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const POLL: Duration = Duration::from_millis(5);

/// Raw paired measurements. Rates are derived, never accepted from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelCompilationResult {
    /// Exact workload definition, independent of the SpeedScore algorithm.
    pub workload_version: u32,
    /// Successfully compiled crates in EACH pass, including the final consumer.
    pub crates: u32,
    /// Actual maximum compiler concurrency requested in the parallel pass.
    pub jobs: u32,
    /// Wall time for the complete serial pass, not the sum of CPU times.
    pub serial_ms: u64,
    /// Wall time for the complete parallel pass.
    pub parallel_ms: u64,
    /// The direct compiler's complete `-vV` identity.
    pub rustc_version: String,
    /// Time at which both passes and output comparison completed.
    pub timestamp: DateTime<Utc>,
}

impl ParallelCompilationResult {
    /// Validate the fixed workload before comparing it with other workers.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.workload_version == PARALLEL_COMPILATION_WORKLOAD_VERSION
            && self.crates == PARALLEL_COMPILATION_CRATES
            && (1..=MAX_PARALLEL_COMPILERS as u32).contains(&self.jobs)
            && self.serial_ms > 0
            && self.parallel_ms > 0
            && self.rustc_version.starts_with("rustc ")
            && self
                .rustc_version
                .lines()
                .any(|line| line.starts_with("host: "))
            && self.rustc_version.len() <= MAX_DIAGNOSTIC_BYTES as usize
    }

    /// Completed compilation work per second, including the serial tail.
    #[must_use]
    pub fn crates_per_second(&self) -> Option<f64> {
        self.is_usable()
            .then(|| f64::from(self.crates) * 1000.0 / self.parallel_ms as f64)
    }

    /// Observed speedup of the parallel pass over the paired serial control.
    /// Values below one are legitimate slowdowns, not clamped successes.
    #[must_use]
    pub fn parallel_speedup(&self) -> Option<f64> {
        self.is_usable()
            .then(|| self.serial_ms as f64 / self.parallel_ms as f64)
    }
}

/// A bounded paired benchmark using the compiler selected on this worker.
#[derive(Debug, Clone)]
pub struct ParallelCompilationBenchmark {
    /// Compiler/proxy to resolve; the probes and builds share its sysroot.
    pub rustc_path: PathBuf,
    /// Requested concurrency, bounded by available parallelism and the cap.
    pub jobs: usize,
    /// One wall-clock budget for setup, probes, warmup and BOTH passes.
    pub timeout: Duration,
}

impl Default for ParallelCompilationBenchmark {
    fn default() -> Self {
        Self {
            rustc_path: PathBuf::from("rustc"),
            jobs: std::thread::available_parallelism().map_or(1, usize::from),
            timeout: Duration::from_secs(120),
        }
    }
}

impl ParallelCompilationBenchmark {
    /// Compile the fixed graph serially and in parallel, with no Cargo clean,
    /// shared target directory, cache wrapper, build script or external crate.
    ///
    /// Errors terminate and reap every compiler started by this benchmark.
    /// This owns direct rustc processes, not arbitrary external executors.
    pub fn run(&self) -> Result<ParallelCompilationResult, CompilationBenchmarkError> {
        if self.jobs == 0 || self.timeout.is_zero() {
            return Err(failure("setup", "jobs and timeout must be positive", None));
        }
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| failure("setup", "benchmark deadline is not representable", None))?;
        let available = std::thread::available_parallelism().map_or(1, usize::from);
        let jobs = self.jobs.min(available).min(MAX_PARALLEL_COMPILERS);
        let root = TempDir::new().map_err(|error| io_failure("setup", error))?;
        let root = root.path();
        let selected_version = probe(&self.rustc_path, "-vV", root, "selected", deadline)?;
        let sysroot = probe(
            &self.rustc_path,
            "--print=sysroot",
            root,
            "sysroot",
            deadline,
        )?;
        let sysroot = Path::new(sysroot.trim());
        if !sysroot.is_absolute() {
            return Err(failure(
                "setup",
                "rustc returned a non-absolute sysroot",
                None,
            ));
        }
        // Resolve rustup ONCE. The pool never measures a cache wrapper or a
        // second machine, and killing one compiler kills its codegen threads.
        let compiler = sysroot
            .join("bin")
            .join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
        let rustc_version = probe(&compiler, "-vV", root, "direct", deadline)?;
        if rustc_version != selected_version {
            return Err(failure(
                "setup",
                "selected and direct compiler identities differ",
                None,
            ));
        }
        setup_sources(root).map_err(|error| io_failure("setup", error))?;
        // Warm the compiler and standard library without reusing any output in
        // either measured pass. No source files change between measurements.
        let warm = root.join("warm");
        fs::create_dir(&warm).map_err(|error| io_failure("setup", error))?;
        let mut warmup = vec![spawn_compile(&compiler, root, &warm, 0, deadline)?];
        finish_pool(&mut warmup, deadline, "warmup")?;
        let serial_ms = run_pass(&compiler, root, "serial", 1, deadline)?;
        let parallel_ms = run_pass(&compiler, root, "parallel", jobs, deadline)?;
        for index in 0..PARALLEL_COMPILATION_CRATES {
            check_deadline(deadline, "verify")?;
            let name = artifact_name(index);
            let same = same_bytes(
                &root.join("serial").join(&name),
                &root.join("parallel").join(name),
                deadline,
            )
            .map_err(|error| io_failure("verify", error))?;
            if !same {
                return Err(failure(
                    "verify",
                    "serial and parallel compiler outputs differ",
                    None,
                ));
            }
        }
        check_deadline(deadline, "verify")?;
        let result = ParallelCompilationResult {
            workload_version: PARALLEL_COMPILATION_WORKLOAD_VERSION,
            crates: PARALLEL_COMPILATION_CRATES,
            jobs: jobs as u32,
            serial_ms,
            parallel_ms,
            rustc_version,
            timestamp: Utc::now(),
        };
        if !result.is_usable() {
            return Err(failure(
                "verify",
                "benchmark produced incomplete measurements",
                None,
            ));
        }
        Ok(result)
    }
}

fn failure(phase: &str, message: &str, stderr: Option<String>) -> CompilationBenchmarkError {
    CompilationBenchmarkError {
        message: message.to_owned(),
        phase: phase.to_owned(),
        stderr,
    }
}

fn io_failure(phase: &str, error: io::Error) -> CompilationBenchmarkError {
    failure(phase, &error.to_string(), None)
}

fn check_deadline(deadline: Instant, phase: &str) -> Result<(), CompilationBenchmarkError> {
    if Instant::now() >= deadline {
        Err(failure(
            phase,
            "parallel compilation benchmark timed out",
            None,
        ))
    } else {
        Ok(())
    }
}

fn probe(
    program: &Path,
    argument: &str,
    root: &Path,
    name: &str,
    deadline: Instant,
) -> Result<String, CompilationBenchmarkError> {
    check_deadline(deadline, "setup")?;
    let stdout = root.join(format!("{name}.stdout"));
    let stderr = root.join(format!("{name}.stderr"));
    let mut command = Command::new(program);
    // Retain the caller's cwd for rustup's project/toolchain selection. Only
    // the measured compilers, resolved to this sysroot, change to the fixture.
    command
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(File::create(&stdout).map_err(|error| io_failure("setup", error))?)
        .stderr(File::create(&stderr).map_err(|error| io_failure("setup", error))?);
    let mut pending = Pending {
        child: Some(
            command
                .spawn()
                .map_err(|error| io_failure("setup", error))?,
        ),
        output: stdout.clone(),
        stderr,
    };
    loop {
        check_deadline(deadline, "setup")?;
        for path in [&pending.output, &pending.stderr] {
            if fs::metadata(path)
                .map_err(|error| io_failure("setup", error))?
                .len()
                > MAX_DIAGNOSTIC_BYTES
            {
                return Err(failure(
                    "setup",
                    "compiler probe exceeds output bound",
                    None,
                ));
            }
        }
        if pending.poll("setup")? {
            check_deadline(deadline, "setup")?;
            let text = read_diagnostic(&stdout).map_err(|error| io_failure("setup", error))?;
            return Ok(text.trim().to_owned());
        }
        std::thread::sleep(POLL);
    }
}

/// An unreaped, directly owned compiler. All outstanding children are killed
/// before any are waited, so an error does not leave the rest of the pool busy.
struct Pending {
    child: Option<Child>,
    output: PathBuf,
    stderr: PathBuf,
}

impl Pending {
    fn poll(&mut self, phase: &str) -> Result<bool, CompilationBenchmarkError> {
        if fs::metadata(&self.stderr)
            .map_err(|error| io_failure(phase, error))?
            .len()
            > MAX_DIAGNOSTIC_BYTES
        {
            return Err(failure(
                phase,
                "compiler diagnostics exceed output bound",
                None,
            ));
        }
        let status = self
            .child
            .as_mut()
            .ok_or_else(|| failure(phase, "compiler already reaped", None))?
            .try_wait()
            .map_err(|error| io_failure(phase, error))?;
        let Some(status) = status else {
            return Ok(false);
        };
        self.child = None;
        if !status.success() {
            return Err(failure(
                phase,
                &format!("rustc exited {status}"),
                read_diagnostic(&self.stderr).ok(),
            ));
        }
        let metadata =
            fs::symlink_metadata(&self.output).map_err(|error| io_failure(phase, error))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(failure(
                phase,
                "compiler did not produce a nonempty regular output",
                None,
            ));
        }
        Ok(true)
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn stop_pool(pool: &mut [Pending]) {
    for pending in pool {
        if let Some(child) = &mut pending.child {
            let _ = child.kill();
        }
    }
}

fn finish_pool(
    pool: &mut Vec<Pending>,
    deadline: Instant,
    phase: &str,
) -> Result<(), CompilationBenchmarkError> {
    let result = (|| {
        while !pool.is_empty() {
            check_deadline(deadline, phase)?;
            let mut index = 0;
            while index < pool.len() {
                if pool[index].poll(phase)? {
                    pool.swap_remove(index);
                } else {
                    index += 1;
                }
            }
            if !pool.is_empty() {
                std::thread::sleep(POLL);
            }
        }
        Ok(())
    })();
    if result.is_err() {
        stop_pool(pool);
        pool.clear();
    }
    result
}

fn run_pass(
    compiler: &Path,
    root: &Path,
    phase: &str,
    jobs: usize,
    deadline: Instant,
) -> Result<u64, CompilationBenchmarkError> {
    let output = root.join(phase);
    fs::create_dir(&output).map_err(|error| io_failure(phase, error))?;
    let start = Instant::now();
    let mut pool = Vec::new();
    let result = (|| {
        let mut next = 0;
        while next < PARALLEL_COMPILATION_CRATES - 1 || !pool.is_empty() {
            check_deadline(deadline, phase)?;
            while next < PARALLEL_COMPILATION_CRATES - 1 && pool.len() < jobs {
                pool.push(spawn_compile(compiler, root, &output, next, deadline)?);
                next += 1;
            }
            let mut index = 0;
            while index < pool.len() {
                if pool[index].poll(phase)? {
                    pool.swap_remove(index);
                } else {
                    index += 1;
                }
            }
            if !pool.is_empty() {
                std::thread::sleep(POLL);
            }
        }
        // The consumer proves that the whole dependency graph was produced;
        // its serial tail is part of both measured durations.
        pool.push(spawn_compile(
            compiler,
            root,
            &output,
            PARALLEL_COMPILATION_CRATES - 1,
            deadline,
        )?);
        finish_pool(&mut pool, deadline, phase)?;
        check_deadline(deadline, phase)?;
        Ok(u64::try_from(start.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1))
    })();
    if result.is_err() {
        stop_pool(&mut pool);
        pool.clear();
    }
    result
}

fn crate_name(index: u32) -> String {
    format!("rch_throughput_{index}")
}

fn artifact_name(index: u32) -> String {
    format!("lib{}.rlib", crate_name(index))
}

fn spawn_compile(
    compiler: &Path,
    root: &Path,
    output: &Path,
    index: u32,
    deadline: Instant,
) -> Result<Pending, CompilationBenchmarkError> {
    check_deadline(deadline, "compile")?;
    let artifact = output.join(artifact_name(index));
    let stderr = output.join(format!("{}.stderr", crate_name(index)));
    let mut command = Command::new(compiler);
    command
        .current_dir(root)
        .arg(root.join(format!("{}.rs", crate_name(index))))
        .args([
            "--crate-type=rlib",
            "--edition=2021",
            "-Copt-level=2",
            "-Ccodegen-units=1",
            "-Cdebuginfo=0",
            "--cap-lints=allow",
        ])
        .arg("--crate-name")
        .arg(crate_name(index))
        .arg("-o")
        .arg(&artifact)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(&stderr).map_err(|error| io_failure("compile", error))?);
    if index == PARALLEL_COMPILATION_CRATES - 1 {
        for dependency in 0..index {
            let mut binding = std::ffi::OsString::from(crate_name(dependency));
            binding.push("=");
            binding.push(output.join(artifact_name(dependency)));
            command.arg("--extern").arg(binding);
        }
    }
    let child = command
        .spawn()
        .map_err(|error| io_failure("compile", error))?;
    Ok(Pending {
        child: Some(child),
        output: artifact,
        stderr,
    })
}

fn read_diagnostic(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_DIAGNOSTIC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DIAGNOSTIC_BYTES {
        return Err(io::Error::other("compiler output exceeds byte bound"));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn same_bytes(first: &Path, second: &Path, deadline: Instant) -> io::Result<bool> {
    let mut first = File::open(first)?;
    let mut second = File::open(second)?;
    if first.metadata()?.len() != second.metadata()?.len() {
        return Ok(false);
    }
    let mut left = [0; 64 * 1024];
    let mut right = [0; 64 * 1024];
    let mut remaining = first.metadata()?.len();
    while remaining > 0 {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "output comparison timed out",
            ));
        }
        let count = remaining.min(left.len() as u64) as usize;
        first.read_exact(&mut left[..count])?;
        second.read_exact(&mut right[..count])?;
        if left[..count] != right[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    Ok(true)
}

fn setup_sources(root: &Path) -> io::Result<()> {
    for index in 0..PARALLEL_COMPILATION_CRATES - 1 {
        fs::write(
            root.join(format!("{}.rs", crate_name(index))),
            LIBRARY_SOURCE,
        )?;
    }
    let mut consumer = String::from("pub fn run(mut value: u64) -> u64 {\n");
    for index in 0..PARALLEL_COMPILATION_CRATES - 1 {
        consumer.push_str(&format!("value = {}::run(value);\n", crate_name(index)));
    }
    consumer.push_str("value\n}\n");
    fs::write(
        root.join(format!(
            "{}.rs",
            crate_name(PARALLEL_COMPILATION_CRATES - 1)
        )),
        consumer,
    )
}

// Exported non-generic work keeps code generation observable in an rlib. No
// runtime benchmark, compile-time sleep, environment read or external crate.
const LIBRARY_SOURCE: &str = r#"
#[inline(never)]
fn mix<const N: usize>(seed: u64) -> u64 {
    let mut values = [seed; N];
    for (index, value) in values.iter_mut().enumerate() {
        *value = value.wrapping_add(index as u64).rotate_left((index % 63) as u32);
    }
    values.sort_unstable();
    values.iter().enumerate().fold(seed, |sum, (index, value)| {
        sum.wrapping_mul(6364136223846793005).wrapping_add(*value ^ index as u64)
    })
}
macro_rules! instantiate {
    ($seed:expr; $($size:expr),*) => {{
        let mut value = $seed;
        $(value = mix::<$size>(value);)*
        value
    }};
}
pub fn run(seed: u64) -> u64 {
    instantiate!(seed; 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59)
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn result() -> ParallelCompilationResult {
        ParallelCompilationResult {
            workload_version: PARALLEL_COMPILATION_WORKLOAD_VERSION,
            crates: PARALLEL_COMPILATION_CRATES,
            jobs: 4,
            serial_ms: 8000,
            parallel_ms: 4000,
            rustc_version: "rustc test\nhost: test-host".to_owned(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn measured_throughput_and_slowdowns_are_not_core_count_estimates() {
        let mut measured = result();
        assert_eq!(measured.crates_per_second(), Some(8.25));
        assert_eq!(measured.parallel_speedup(), Some(2.0));
        measured.jobs = 16;
        assert_eq!(measured.crates_per_second(), Some(8.25));
        measured.parallel_ms = 16000;
        assert_eq!(measured.parallel_speedup(), Some(0.5));
        assert_eq!(measured.crates_per_second(), Some(2.0625));
    }

    #[test]
    fn incompatible_or_incomplete_measurements_are_not_scored() {
        let original = result();
        let mut cases = Vec::new();
        for jobs in [0, MAX_PARALLEL_COMPILERS as u32 + 1] {
            cases.push(ParallelCompilationResult {
                jobs,
                ..original.clone()
            });
        }
        cases.push(ParallelCompilationResult {
            workload_version: 0,
            ..original.clone()
        });
        cases.push(ParallelCompilationResult {
            crates: 1,
            ..original.clone()
        });
        cases.push(ParallelCompilationResult {
            serial_ms: 0,
            ..original.clone()
        });
        cases.push(ParallelCompilationResult {
            parallel_ms: 0,
            ..original.clone()
        });
        cases.push(ParallelCompilationResult {
            rustc_version: String::new(),
            ..original
        });
        for measured in cases {
            assert_eq!(measured.crates_per_second(), None);
            assert_eq!(measured.parallel_speedup(), None);
        }
    }

    #[test]
    fn source_graph_is_fixed_and_has_no_cargo_or_shared_output_state() {
        let root = TempDir::new().unwrap();
        setup_sources(root.path()).unwrap();
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            PARALLEL_COMPILATION_CRATES as usize
        );
        let consumer = fs::read_to_string(root.path().join("rch_throughput_32.rs")).unwrap();
        for index in 0..32 {
            assert_eq!(
                fs::read_to_string(root.path().join(format!("rch_throughput_{index}.rs"))).unwrap(),
                LIBRARY_SOURCE
            );
            assert!(consumer.contains(&format!("rch_throughput_{index}::run(value)")));
        }
        assert!(!root.path().join("Cargo.toml").exists());
    }

    #[test]
    fn invalid_configuration_starts_no_compiler() {
        let mut benchmark = ParallelCompilationBenchmark {
            rustc_path: PathBuf::from("/does-not-exist"),
            jobs: 0,
            timeout: Duration::from_secs(1),
        };
        assert_eq!(
            benchmark.run().unwrap_err().message,
            "jobs and timeout must be positive"
        );
        benchmark.jobs = 1;
        benchmark.timeout = Duration::ZERO;
        assert_eq!(
            benchmark.run().unwrap_err().message,
            "jobs and timeout must be positive"
        );
    }

    #[test]
    fn output_comparison_refuses_mutation_missing_bytes_and_expired_budget() {
        let root = TempDir::new().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        let bytes = vec![42; 131_073];
        fs::write(&first, &bytes).unwrap();
        fs::write(&second, &bytes).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(same_bytes(&first, &second, deadline).unwrap());
        assert!(same_bytes(&first, &second, Instant::now()).is_err());
        fs::write(&second, vec![41; bytes.len()]).unwrap();
        assert!(!same_bytes(&first, &second, deadline).unwrap());
        fs::write(&second, [42]).unwrap();
        assert!(!same_bytes(&first, &second, deadline).unwrap());
    }

    #[test]
    fn result_roundtrips_with_exact_workload_and_compiler_identity() {
        let original = result();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ParallelCompilationResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_usable());
        assert_eq!(decoded.rustc_version, original.rustc_version);
        assert_eq!(decoded.parallel_speedup(), original.parallel_speedup());
    }

    #[test]
    #[ignore = "executes 67 real rustc compilations; run explicitly on an idle/admitted worker"]
    fn real_compiler_builds_byte_identical_serial_and_parallel_graphs() {
        let benchmark = ParallelCompilationBenchmark {
            jobs: 2,
            ..Default::default()
        };
        let result = benchmark.run().expect("real paired compilation");
        assert!(result.is_usable());
        assert!(result.jobs <= 2);
        assert!(result.crates_per_second().unwrap() > 0.0);
        // No speedup threshold: reporting a parallel slowdown is valid evidence.
    }
}
