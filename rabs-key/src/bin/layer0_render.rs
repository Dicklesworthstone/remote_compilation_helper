//! Render the host's Layer-0 config pack (bead B015 driver support):
//! assembles the B014 pack from ambient toolchain evidence and prints
//! the Cargo config to stdout, so the benchmark script can apply the
//! layer0 variant exactly as the pack defines it.
use rabs_key::layer0_pack::{PackEvidence, assemble};
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
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
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
                    "Usage: layer0_render [--rustc PATH] [--zthreads COUNT]\n\nUnstable threads are OFF unless explicitly requested and the selected nightly\nreports support. --rustc defaults to RUSTC, then rustc on PATH. Apply the rendered\nCargo config only with that same compiler/toolchain. Existing Cargo env/target\nrustflags take Cargo's normal precedence; no wrappers or user files are changed."
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    let (version_line, rustc_z_help) = compiler_evidence(&compiler, threads.is_some())?;
    let mut linker_version_lines = Vec::new();
    for linker in ["wild", "ld.lld", "lld", "mold"] {
        if let Ok(output) = std::process::Command::new(linker).arg("--version").output()
            && output.status.success()
            && let Some(first) = String::from_utf8_lossy(&output.stdout).lines().next()
        {
            linker_version_lines.push(first.to_string());
        }
    }
    let evidence = PackEvidence {
        rustc_version_line: version_line,
        rustc_z_help,
        zthreads: threads,
        linker_version_lines,
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
    print!("{}", pack.render_config());
    Ok(())
}

fn compiler_evidence(
    compiler: &std::ffi::OsStr,
    probe_threads: bool,
) -> Result<(String, Option<String>), String> {
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
    Ok((version_line, rustc_z_help))
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
            let (version, help) = compiler_evidence(compiler.as_ref(), true).unwrap();
            eprintln!("channel={channel} compiler={compiler} version={version}");
            let mut evidence = PackEvidence {
                rustc_version_line: version,
                rustc_z_help: help,
                zthreads: NonZeroU32::new(2),
                linker_version_lines: Vec::new(),
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
