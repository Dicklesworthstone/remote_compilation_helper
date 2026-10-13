//! Private Cargo execution for the worker's compilation benchmark.
//!
//! Cargo's target directory and intermediate build directory are independent.
//! Pin both, disable cache wrappers, and use the compiler whose identity was
//! probed. These settings belong to child commands, never the worker process.

use super::CompilationBenchmarkError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(super) struct BuildContext {
    cargo: PathBuf,
    compiler: PathBuf,
    host: String,
    pub(super) version: String,
}

fn failure(message: impl Into<String>) -> CompilationBenchmarkError {
    CompilationBenchmarkError {
        message: message.into(),
        phase: "setup".to_owned(),
        stderr: None,
    }
}

/// Resolve caller-relative paths before switching to a generated project.
/// Bare executable names still use the caller's PATH in the initial probe.
fn caller_path(program: &Path) -> Result<PathBuf, CompilationBenchmarkError> {
    if program.is_absolute() || program.components().count() == 1 {
        Ok(program.to_owned())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(program))
            .map_err(|error| failure(format!("Cannot resolve benchmark tool path: {error}")))
    }
}

fn probe(program: &Path, argument: &str) -> Result<String, CompilationBenchmarkError> {
    let output = Command::new(program)
        .arg(argument)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| failure(format!("Cannot probe benchmark compiler: {error}")))?;
    if !output.status.success() {
        return Err(CompilationBenchmarkError {
            message: format!(
                "Benchmark compiler probe {argument} failed: {}",
                output.status
            ),
            phase: "setup".to_owned(),
            stderr: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
        });
    }
    String::from_utf8(output.stdout).map_err(|_| failure("Benchmark compiler probe is not UTF-8"))
}

fn compiler_host(version: &str) -> Result<String, CompilationBenchmarkError> {
    let mut hosts = version
        .lines()
        .filter_map(|line| line.strip_prefix("host: "));
    let host = hosts
        .next()
        .ok_or_else(|| failure("Compiler identity has no host"))?;
    if !version.starts_with("rustc ")
        || hosts.next().is_some()
        || host.is_empty()
        || host.starts_with('-')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(failure("Invalid or ambiguous benchmark compiler identity"));
    }
    Ok(host.to_owned())
}

fn cargo_path_setting(key: &str, path: &Path) -> Result<String, CompilationBenchmarkError> {
    let text = path
        .to_str()
        .ok_or_else(|| failure("Benchmark path is not representable in Cargo configuration"))?;
    // JSON strings use TOML-compatible basic-string escapes here, including
    // quotes and Windows backslashes. Never interpolate a raw path into TOML.
    let quoted = serde_json::to_string(text).map_err(|error| failure(error.to_string()))?;
    Ok(format!("{key}={quoted}"))
}

impl BuildContext {
    pub(super) fn resolve(cargo: &Path, rustc: &Path) -> Result<Self, CompilationBenchmarkError> {
        let cargo = caller_path(cargo)?;
        let selected = caller_path(rustc)?;
        let version = probe(&selected, "-vV")?;
        let host = compiler_host(&version)?;
        let sysroot = probe(&selected, "--print=sysroot")?;
        let sysroot = sysroot.trim_end_matches(['\r', '\n']);
        if sysroot.is_empty() || sysroot.contains(['\r', '\n']) || !Path::new(sysroot).is_absolute()
        {
            return Err(failure("Compiler returned an invalid absolute sysroot"));
        }
        let compiler = Path::new(sysroot)
            .join("bin")
            .join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
        let direct_version = probe(&compiler, "-vV")?;
        if direct_version != version {
            return Err(failure(
                "Selected and direct benchmark compiler identities differ",
            ));
        }
        Ok(Self {
            cargo,
            compiler,
            host,
            version: version.trim_end().to_owned(),
        })
    }

    /// Every phase owns a freshly generated project. Only the two incremental
    /// builds share a project/target directory. There is no `cargo clean` path.
    pub(super) fn command(
        &self,
        project: &Path,
        release: bool,
        incremental: bool,
    ) -> Result<Command, CompilationBenchmarkError> {
        let project = std::fs::canonicalize(project).map_err(|error| {
            failure(format!("Cannot resolve private benchmark project: {error}"))
        })?;
        let target = project.join("target");
        let mut command = Command::new(&self.cargo);
        command
            .arg("build")
            .arg("--offline")
            .args(["--jobs", "1"])
            .arg("--manifest-path")
            .arg(project.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .arg("--target")
            .arg(&self.host)
            .arg("--profile")
            .arg(if release { "release" } else { "dev" })
            .arg("--config")
            .arg(cargo_path_setting("build.build-dir", &target)?)
            .arg("--config")
            .arg(cargo_path_setting("build.rustc", &self.compiler)?)
            .args(["--config", "build.rustc-wrapper=\"\""])
            .args(["--config", "build.rustc-workspace-wrapper=\"\""])
            .args(["--config", "cache.auto-clean-frequency=\"never\""])
            .current_dir(&project)
            .stdin(Stdio::null())
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_BUILD_TARGET_DIR", &target)
            .env("CARGO_BUILD_BUILD_DIR", &target)
            .env("CARGO_CACHE_AUTO_CLEAN_FREQUENCY", "never")
            .env("RUSTC", &self.compiler)
            .env("CARGO_BUILD_RUSTC", &self.compiler)
            .env("RUSTC_WRAPPER", "")
            .env("RUSTC_WORKSPACE_WRAPPER", "")
            .env("CARGO_BUILD_RUSTC_WRAPPER", "")
            .env("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "")
            .env("CARGO_ENCODED_RUSTFLAGS", "")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env("CARGO_INCREMENTAL", if incremental { "1" } else { "0" })
            .env("CARGO_TERM_COLOR", "never")
            // This is the worker's own benchmark, not a caller build to offload.
            .env("RCH_CARGO_WRAPPER_BYPASS", "1")
            .env("RCH_ENABLED", "0");
        Ok(command)
    }

    pub(super) fn verify_output(
        &self,
        project: &Path,
        release: bool,
    ) -> Result<(), CompilationBenchmarkError> {
        let executable = project
            .join("target")
            .join(&self.host)
            .join(if release { "release" } else { "debug" })
            .join(format!("rch_benchmark{}", std::env::consts::EXE_SUFFIX));
        let metadata = std::fs::symlink_metadata(&executable).map_err(|error| {
            failure(format!(
                "Benchmark build did not produce its private executable: {error}"
            ))
        })?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(failure(
                "Benchmark output is not a nonempty regular executable file",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn context() -> BuildContext {
        BuildContext {
            cargo: PathBuf::from("chosen-cargo"),
            compiler: PathBuf::from("/selected toolchain/bin/rustc"),
            host: "x86_64-unknown-linux-gnu".into(),
            version: "rustc fixture\nhost: x86_64-unknown-linux-gnu".into(),
        }
    }

    #[test]
    fn both_output_roots_and_compiler_are_explicit_on_every_phase() {
        let directory = tempfile::Builder::new()
            .prefix("rch bench ' ")
            .tempdir()
            .unwrap();
        let root = directory.path().canonicalize().unwrap();
        for (release, incremental) in [(false, false), (true, false), (true, true)] {
            let command = context().command(&root, release, incremental).unwrap();
            let args: Vec<_> = command.get_args().collect();
            let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
            assert_eq!(command.get_program(), "chosen-cargo");
            assert_eq!(command.get_current_dir(), Some(root.as_path()));
            assert_eq!(args[0], "build");
            assert!(!args.contains(&OsStr::new("clean")));
            for name in [
                "CARGO_TARGET_DIR",
                "CARGO_BUILD_TARGET_DIR",
                "CARGO_BUILD_BUILD_DIR",
            ] {
                assert_eq!(env[OsStr::new(name)], Some(root.join("target").as_os_str()));
            }
            assert_eq!(
                env[OsStr::new("RUSTC")],
                Some(OsStr::new("/selected toolchain/bin/rustc"))
            );
            assert_eq!(
                env[OsStr::new("CARGO_INCREMENTAL")],
                Some(OsStr::new(if incremental { "1" } else { "0" }))
            );
            let target = root.join("target");
            assert!(
                args.windows(2)
                    .any(|pair| pair == [OsStr::new("--target-dir"), target.as_os_str()])
            );
            let setting = cargo_path_setting("build.build-dir", &target).unwrap();
            assert!(args.contains(&OsStr::new(&setting)));
        }
    }

    #[test]
    fn cache_wrappers_flags_and_global_cleaning_are_not_inherited() {
        let directory = tempfile::tempdir().unwrap();
        let command = context().command(directory.path(), true, false).unwrap();
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for name in [
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
        ] {
            assert_eq!(env[OsStr::new(name)], Some(OsStr::new("")));
        }
        assert_eq!(env[OsStr::new("RUSTFLAGS")], None);
        assert_eq!(env[OsStr::new("CARGO_BUILD_RUSTFLAGS")], None);
        assert_eq!(
            env[OsStr::new("CARGO_CACHE_AUTO_CLEAN_FREQUENCY")],
            Some(OsStr::new("never"))
        );
    }

    #[test]
    fn identity_needs_one_literal_host() {
        assert_eq!(
            compiler_host("rustc 1.90\nhost: x86_64-unknown-linux-gnu\n").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        for identity in [
            "rustc unknown",
            "rustc unknown\nhost: \n",
            "rustc unknown\nhost: a\nhost: b\n",
            "rustc unknown\nhost: --help\n",
            "rustc unknown\nhost: a b\n",
            "other\nhost: a\n",
        ] {
            assert!(compiler_host(identity).is_err(), "{identity}");
        }
    }

    #[test]
    fn command_paths_are_not_toml_fragments() {
        let text = "C:\\private ' benchmark\\a\"b";
        let setting = cargo_path_setting("build.build-dir", Path::new(text)).unwrap();
        let encoded = setting.strip_prefix("build.build-dir=").unwrap();
        assert_eq!(serde_json::from_str::<String>(encoded).unwrap(), text);
        assert_eq!(caller_path(Path::new("cargo")).unwrap(), Path::new("cargo"));
        assert!(caller_path(Path::new("tools/cargo")).unwrap().is_absolute());
    }

    #[test]
    fn missing_empty_and_symlinked_outputs_cannot_be_measurements() {
        let directory = tempfile::tempdir().unwrap();
        let context = context();
        assert!(context.verify_output(directory.path(), true).is_err());
        let output = directory
            .path()
            .join("target")
            .join(&context.host)
            .join("release")
            .join(format!("rch_benchmark{}", std::env::consts::EXE_SUFFIX));
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        std::fs::write(&output, b"").unwrap();
        assert!(context.verify_output(directory.path(), true).is_err());
        std::fs::write(&output, b"fixture executable").unwrap();
        context.verify_output(directory.path(), true).unwrap();
        #[cfg(unix)]
        {
            let saved = output.with_extension("saved");
            std::fs::rename(&output, &saved).unwrap();
            std::os::unix::fs::symlink(&saved, &output).unwrap();
            assert!(context.verify_output(directory.path(), true).is_err());
        }
    }
}
