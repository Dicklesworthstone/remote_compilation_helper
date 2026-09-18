//! Render the host's Layer-0 config pack (bead B015 driver support):
//! assembles the B014 pack from ambient toolchain evidence and prints
//! the Cargo config to stdout, so the benchmark script can apply the
//! layer0 variant exactly as the pack defines it.
use rabs_key::layer0_pack::{AppleSdkBaseline, PackEvidence, assemble};
use std::{ffi::OsString, num::NonZeroU32, process::Command};

fn main() {
    if let Err(error) = run() {
        eprintln!("layer0_render: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut compiler = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut threads = None;
    let mut line_tables_only = false;
    let mut split_debuginfo_unpacked = false;
    let mut cranelift_dev_backend = false;
    let mut target_cpu_baseline = None;
    let mut apple_deployment_target = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--line-tables-only") => line_tables_only = true,
            Some("--split-debuginfo-unpacked") => split_debuginfo_unpacked = true,
            Some("--cranelift") => cranelift_dev_backend = true,
            Some("--target-cpu") => {
                target_cpu_baseline = Some(
                    args.next()
                        .and_then(|v| v.into_string().ok())
                        .ok_or("--target-cpu needs a baseline name")?,
                );
            }
            Some("--deployment-target") => {
                apple_deployment_target = Some(
                    args.next()
                        .and_then(|v| v.into_string().ok())
                        .ok_or("--deployment-target needs a version")?,
                );
            }
            Some("--rustc") => compiler = args.next().ok_or("--rustc needs an executable path")?,
            Some("--zthreads") => {
                threads = Some(
                    args.next()
                        .and_then(|v| v.to_str().and_then(|s| s.parse::<NonZeroU32>().ok()))
                        .ok_or("--zthreads needs a positive u32 count")?,
                );
            }
            Some("--help" | "-h") => {
                println!(
                    "Usage: layer0_render [--rustc PATH] [--zthreads COUNT] [--line-tables-only] [--split-debuginfo-unpacked]\n                     [--cranelift] [--target-cpu BASELINE] [--deployment-target VERSION]\n\nDebug settings are preserved unless explicitly requested. --line-tables-only\nkeeps source breakpoints/backtraces but removes variable/type information.\n--split-debuginfo-unpacked requires retaining separate debug files with the binary;\ncheck support on the selected target. Both affect the dev profile.\nUnstable threads are OFF unless explicitly requested and the selected nightly\nreports support. --cranelift is likewise opt-in and requires the nightly codegen\nbackend to be installed; it applies to the dev profile only and keeps build\nscripts and proc macros on LLVM. --target-cpu pins an explicit portable baseline;\nmachine-relative spellings such as `native` are refused because they resolve\ndifferently on every host. --deployment-target applies on Apple hosts, where the\nSDK baseline is probed with xcrun. A faster linker is selected only when the\nclang driver that carries its flag is present and the host triple has a spelling\nin the pack. --rustc defaults to RUSTC, then rustc on PATH. Apply the rendered\nCargo config only with that same compiler/toolchain. Existing Cargo env/target\nrustflags take Cargo's normal precedence; no wrappers or user files are changed."
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    let (version_line, host_target_triple, rustc_z_help) =
        compiler_evidence(&compiler, threads.is_some())?;
    let mut linker_version_lines = Vec::new();
    // Only families the pack can actually SELECT are probed: a version line
    // this pack has no flag spelling for would be collected and then silently
    // discarded, which reads like a rejected candidate when it was never one.
    for linker in ["wild", "ld.lld", "lld"] {
        if let Ok(output) = std::process::Command::new(linker).arg("--version").output()
            && output.status.success()
            && let Some(first) = String::from_utf8_lossy(&output.stdout).lines().next()
        {
            linker_version_lines.push(first.to_string());
        }
    }
    let apple_sdk = if host_target_triple.contains("-apple-") {
        apple_sdk_baseline()
    } else {
        None
    };
    let evidence = PackEvidence {
        rustc_version_line: version_line,
        rustc_z_help,
        zthreads: threads,
        line_tables_only,
        split_debuginfo_unpacked,
        linker_version_lines,
        cranelift_backend_library: cranelift_backend(&compiler, &host_target_triple),
        cranelift_dev_backend,
        target_cpu_baseline,
        apple_deployment_target,
        apple_sdk,
        // The flag spellings this pack renders are carried by the clang
        // driver; without it, `linker = "clang"` breaks every build.
        linker_driver_available: probe("clang", "--version"),
        host_target_triple,
        sccache_available: probe("sccache", "--version"),
        hakari_available: probe("cargo", "hakari"),
    };
    let pack = assemble(&evidence);
    if threads.is_some()
        && !pack
            .knobs
            .iter()
            .any(|k| k.id == "zthreads-parallel-frontend" && k.enabled)
    {
        eprintln!(
            "layer0_render: requested threads disabled: selected compiler lacks proven nightly support"
        );
    }
    if cranelift_dev_backend
        && !pack
            .knobs
            .iter()
            .any(|k| k.id == "codegen-backend-cranelift" && k.enabled)
    {
        eprintln!(
            "layer0_render: requested cranelift disabled: selected compiler has no installed codegen backend"
        );
    }
    print!("{}", pack.render_config());
    Ok(())
}

/// The Cranelift backend library the SELECTED compiler would load, if its
/// sysroot carries one. Probed from that compiler's own sysroot rather than
/// from PATH: a second toolchain's backend cannot be loaded by this one.
fn cranelift_backend(compiler: &std::ffi::OsStr, host: &str) -> Option<String> {
    let sysroot = Command::new(compiler)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_owned();
    let backends = std::path::Path::new(&sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("codegen-backends");
    std::fs::read_dir(backends)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("cranelift"))
        })
        .map(|path| path.display().to_string())
}

/// The Apple SDK baseline, probed with `xcrun`. Version and path travel
/// together: a version alone cannot be pinned, a path alone cannot be
/// compared across machines.
fn apple_sdk_baseline() -> Option<AppleSdkBaseline> {
    let show = |flag: &str| {
        Command::new("xcrun")
            .arg(flag)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    Some(AppleSdkBaseline {
        version: show("--show-sdk-version")?,
        path: show("--show-sdk-path")?,
    })
}

fn compiler_evidence(
    compiler: &std::ffi::OsStr,
    probe_threads: bool,
) -> Result<(String, String, Option<String>), String> {
    let rustc = Command::new(compiler)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .arg("-vV")
        .output()
        .map_err(|e| format!("cannot probe {compiler:?}: {e}"))?;
    if !rustc.status.success() {
        return Err(format!(
            "{compiler:?} -vV failed: {}",
            String::from_utf8_lossy(&rustc.stderr)
        ));
    }
    let version = String::from_utf8_lossy(&rustc.stdout).into_owned();
    let version_line = version.lines().next().unwrap_or("").to_string();
    // `rustc -vV` reports the host triple; every `[target.*]` section the
    // pack renders is keyed on it, so it comes from the SAME probe as the
    // version rather than from the builder's own compile-time target.
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| format!("{compiler:?} -vV reported no host triple"))?
        .trim()
        .to_owned();
    let rustc_z_help = if probe_threads {
        let output = Command::new(compiler)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .args(["-Z", "help"])
            .output()
            .map_err(|e| format!("cannot probe {compiler:?} -Z help: {e}"))?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            eprintln!(
                "layer0_render: threads capability probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            None
        }
    } else {
        None
    };
    Ok((version_line, host, rustc_z_help))
}

fn probe(bin: &str, arg: &str) -> bool {
    std::process::Command::new(bin)
        .arg(arg)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires GDB and explicit RCH_L0_DEBUG_TOOLCHAIN; run with --ignored on the remote validation worker"]
    fn layer0_real_debug_breakpoints_and_size_time() {
        let channel = std::env::var("RCH_L0_DEBUG_TOOLCHAIN").expect("explicit toolchain required");
        let retained = tempfile::Builder::new()
            .prefix("rch-layer0-debug-")
            .tempdir_in("/tmp")
            .unwrap()
            .keep();
        eprintln!("retained debug benchmark: {}", retained.display());
        let which = |program| {
            let output = Command::new("rustup")
                .env("RUSTUP_AUTO_INSTALL", "0")
                .args(["which", "--toolchain", &channel, program])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let compiler = which("rustc");
        let cargo = which("cargo");
        let (version, host, _) = compiler_evidence(compiler.as_ref(), false).unwrap();
        eprintln!("compiler={compiler} version={version}");
        let mut measurements = Vec::new();
        // Three fresh-target samples per combination. Rotate ordering to avoid
        // attributing the first Cargo/filesystem warmup to a particular knob.
        let variants = [
            ("full", false, false),
            ("lines", true, false),
            ("split", false, true),
            ("lines-split", true, true),
        ];
        for sample in 0..3 {
            for offset in 0..variants.len() {
                let (label, lines, split) = variants[(offset + sample) % variants.len()];
                let project = retained.join(format!("{label}-{sample}"));
                std::fs::create_dir_all(project.join("src")).unwrap();
                std::fs::write(project.join("Cargo.toml"), "[package]\nname='layer0_debug_real'\nversion='0.0.0'\nedition='2021'\n[workspace]\n[profile.dev]\ndebug='full'\nsplit-debuginfo='off'\n").unwrap();
                std::fs::write(project.join("src/main.rs"), "#[inline(never)]\nfn calculate(values: &[u64]) -> u64 {\n    let doubled: Vec<u64> = values.iter().map(|v| v * 2).collect();\n    let answer: u64 = doubled.iter().sum();\n    std::hint::black_box(answer)\n}\nfn main() { println!(\"{}\", calculate(&[3, 7, 11])); }\n").unwrap();
                let evidence = PackEvidence {
                    rustc_version_line: version.clone(),
                    rustc_z_help: None,
                    zthreads: None,
                    line_tables_only: lines,
                    split_debuginfo_unpacked: split,
                    linker_version_lines: Vec::new(),
                    host_target_triple: host.clone(),
                    linker_driver_available: false,
                    cranelift_backend_library: None,
                    cranelift_dev_backend: false,
                    target_cpu_baseline: None,
                    apple_deployment_target: None,
                    apple_sdk: None,
                    sccache_available: false,
                    hakari_available: false,
                };
                let config = project.join("layer0.toml");
                std::fs::write(&config, assemble(&evidence).render_config()).unwrap();
                let target = project.join("target");
                let started = std::time::Instant::now();
                let output = Command::new(&cargo)
                    .current_dir(&project)
                    .env("RUSTC", &compiler)
                    .env("RUSTUP_TOOLCHAIN", &channel)
                    .env("RUSTUP_AUTO_INSTALL", "0")
                    .env("RCH_CARGO_WRAPPER_BYPASS", "1")
                    .env("CARGO_HOME", retained.join("cargo-home"))
                    .env("CARGO_TARGET_DIR", &target)
                    .env("CARGO_INCREMENTAL", "0")
                    .env_remove("RUSTFLAGS")
                    .env_remove("CARGO_ENCODED_RUSTFLAGS")
                    .env_remove("CARGO_BUILD_RUSTFLAGS")
                    .env_remove("RUSTC_WRAPPER")
                    .env_remove("RUSTC_WORKSPACE_WRAPPER")
                    .env_remove("CARGO_PROFILE_DEV_DEBUG")
                    .env_remove("CARGO_PROFILE_DEV_SPLIT_DEBUGINFO")
                    .env_remove("CARGO_BUILD_TARGET")
                    .env_remove("CARGO_BUILD_BUILD_DIR")
                    .args(["build", "--offline", "--verbose", "--jobs", "1", "--config"])
                    .arg(&config)
                    .output()
                    .unwrap();
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                std::fs::write(project.join("cargo.stdout"), &output.stdout).unwrap();
                std::fs::write(project.join("cargo.stderr"), &output.stderr).unwrap();
                assert!(
                    output.status.success(),
                    "{label}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let executable = target.join("debug/layer0_debug_real");
                let run = Command::new(&executable).output().unwrap();
                assert!(run.status.success());
                assert_eq!(String::from_utf8_lossy(&run.stdout).trim(), "42");
                // GDB launches only this owned inferior; no system ptrace policy
                // change or attachment to another process is necessary.
                let mut debugger = Command::new("timeout");
                debugger.args(["30s", "gdb", "--batch", "-nx", "-ex", "set debuginfod enabled off", "-ex", "set pagination off", "-ex", "break src/main.rs:5", "-ex", "run", "-ex", "python assert gdb.selected_frame().find_sal().line == 5", "-ex", "python assert gdb.selected_frame().find_sal().symtab.fullname().endswith('/src/main.rs')"]);
                if !lines {
                    debugger.args([
                        "-ex",
                        "python assert int(gdb.parse_and_eval('answer')) == 42; print('GDB_VARIABLE_VERIFIED')",
                    ]);
                }
                let debug = debugger
                    .args([
                        "-ex",
                        "python print('GDB_PYTHON_AVAILABLE')",
                        "-ex",
                        "continue",
                        "--args",
                    ])
                    .arg(&executable)
                    .current_dir(&project)
                    .output()
                    .unwrap();
                std::fs::write(project.join("gdb.stdout"), &debug.stdout).unwrap();
                std::fs::write(project.join("gdb.stderr"), &debug.stderr).unwrap();
                let stdout = String::from_utf8_lossy(&debug.stdout);
                let stderr = String::from_utf8_lossy(&debug.stderr);
                assert!(
                    debug.status.success()
                        && !stderr.contains("Traceback")
                        && !stderr.contains("Error while executing Python"),
                    "{label}: {stdout}\n{stderr}"
                );
                assert!(
                    stdout.contains("Breakpoint 1,")
                        && stdout.contains("exited normally")
                        && stdout.contains("GDB_PYTHON_AVAILABLE"),
                    "{label}: {stdout}\n{stderr}"
                );
                if !lines {
                    assert!(
                        stdout.contains("GDB_VARIABLE_VERIFIED"),
                        "{label}: {stdout}\n{stderr}"
                    );
                }
                let binary_bytes = std::fs::metadata(&executable).unwrap().len();
                let mut split_bytes = 0;
                // Cargo's build-dir layout differs across toolchains. Count
                // retained DWARF files throughout this owned target, not just
                // the legacy debug/deps directory.
                let mut directories = vec![target.clone()];
                while let Some(directory) = directories.pop() {
                    for entry in std::fs::read_dir(directory).unwrap() {
                        let entry = entry.unwrap();
                        if entry.file_type().unwrap().is_dir() {
                            directories.push(entry.path());
                        } else if entry.path().extension().is_some_and(|ext| ext == "dwo") {
                            split_bytes += entry.metadata().unwrap().len();
                        }
                    }
                }
                if split && !lines {
                    assert!(
                        split_bytes > 0,
                        "full unpacked mode must retain separate debug data"
                    );
                }
                let row = serde_json::json!({"variant": label, "sample": sample, "elapsed_ms": elapsed_ms, "binary_bytes": binary_bytes, "split_bytes": split_bytes, "debug_bundle_bytes": binary_bytes + split_bytes});
                eprintln!("debug measurement {row}");
                measurements.push(row);
            }
        }
        std::fs::write(
            retained.join("measurements.json"),
            serde_json::to_vec_pretty(&measurements).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires explicit RCH_L0_STABLE_TOOLCHAIN and RCH_L0_NIGHTLY_TOOLCHAIN; run with --ignored on the remote validation worker"]
    fn layer0_real_compilers_render_and_compile_supported_and_unsupported() {
        let retained = tempfile::Builder::new()
            .prefix("rch-layer0-threads-")
            .tempdir_in("/tmp")
            .unwrap()
            .keep();
        eprintln!("retained Layer 0 compiler fixture: {}", retained.display());
        for (label, variable, supported) in [
            ("stable", "RCH_L0_STABLE_TOOLCHAIN", false),
            ("nightly", "RCH_L0_NIGHTLY_TOOLCHAIN", true),
        ] {
            let selected = std::env::var(variable).expect("explicit toolchain input is required");
            let channel = selected.as_str();
            let which = |program| {
                let output = Command::new("rustup")
                    .env("RUSTUP_AUTO_INSTALL", "0")
                    .args(["which", "--toolchain", channel, program])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{channel} {program}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout).unwrap().trim().to_owned()
            };
            let compiler = which("rustc");
            let cargo = which("cargo");
            let (version, host, help) = compiler_evidence(compiler.as_ref(), true).unwrap();
            eprintln!("channel={channel} compiler={compiler} version={version}");
            let mut evidence = PackEvidence {
                rustc_version_line: version,
                rustc_z_help: help,
                zthreads: NonZeroU32::new(2),
                line_tables_only: false,
                split_debuginfo_unpacked: false,
                linker_version_lines: Vec::new(),
                host_target_triple: host,
                linker_driver_available: false,
                cranelift_backend_library: None,
                cranelift_dev_backend: false,
                target_cpu_baseline: None,
                apple_deployment_target: None,
                apple_sdk: None,
                sccache_available: false,
                hakari_available: false,
            };
            let config = assemble(&evidence).render_config();
            assert_eq!(config.contains("-Zthreads=2"), supported);
            evidence.zthreads = None;
            assert!(!assemble(&evidence).render_config().contains("-Zthreads"));
            let project = retained.join(label);
            std::fs::create_dir_all(project.join("src")).unwrap();
            std::fs::write(project.join("Cargo.toml"), "[package]\nname='layer0_threads_real'\nversion='0.0.0'\nedition='2021'\n[workspace]\n").unwrap();
            std::fs::write(project.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n#[test] fn real_execution() { assert_eq!(answer(), 42); }\n").unwrap();
            let config_path = project.join("layer0.toml");
            std::fs::write(&config_path, config).unwrap();
            let output = Command::new(cargo)
                .current_dir(&project)
                .env("RUSTC", &compiler)
                .env("RUSTUP_TOOLCHAIN", channel)
                .env("RUSTUP_AUTO_INSTALL", "0")
                .env("RCH_CARGO_WRAPPER_BYPASS", "1")
                .env("CARGO_HOME", project.join("cargo-home"))
                .env("CARGO_TARGET_DIR", project.join("target"))
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_RUSTFLAGS")
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("RUSTC_BOOTSTRAP")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_BUILD_BUILD_DIR")
                .args([
                    "test",
                    "--offline",
                    "--lib",
                    "--verbose",
                    "--jobs",
                    "1",
                    "--config",
                ])
                .arg(&config_path)
                .output()
                .unwrap();
            std::fs::write(project.join("cargo.stdout"), &output.stdout).unwrap();
            std::fs::write(project.join("cargo.stderr"), &output.stderr).unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{channel} Cargo stdout:\n{stdout}\nCargo stderr:\n{stderr}");
            assert!(output.status.success(), "{channel} Cargo failed");
            assert!(stdout.contains("1 passed; 0 failed"));
            let invocation = stderr
                .lines()
                .find(|line| {
                    line.contains(&compiler) && line.contains("--crate-name layer0_threads_real")
                })
                .expect("verbose Cargo must show the selected compiler invocation");
            assert_eq!(invocation.contains("-Zthreads=2"), supported);
        }
    }
}
