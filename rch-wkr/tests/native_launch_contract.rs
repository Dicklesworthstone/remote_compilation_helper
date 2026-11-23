//! Production shell contracts for native launch and timeout helpers.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("native-launch-contract-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap()
}

fn installed_rustc() -> PathBuf {
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(compiler)
        .args(["--print", "sysroot"])
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .expect("resolve the installed test compiler before changing the child PATH");
    assert!(output.status.success(), "{output:?}");
    let sysroot = String::from_utf8(output.stdout).unwrap();
    let compiler = Path::new(sysroot.trim()).join("bin/rustc");
    let compiler = std::fs::canonicalize(compiler).expect("installed toolchain compiler");
    assert!(compiler.is_file(), "{}", compiler.display());
    compiler
}

fn compiler_script(directory: &Path, source: &str) {
    let path = directory.join("rustc");
    std::fs::write(&path, format!("#!/bin/sh\n{source}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn native_runtime_probe_cli_compiles_and_runs_fresh_programs() {
    let rustc = installed_rustc();
    let directory = fixture();
    let bin = directory.path().join("bin");
    let temporary = directory.path().join("temporary");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&temporary).unwrap();
    let temporary = std::fs::canonicalize(temporary).unwrap();
    let compilations = directory.path().join("compilations");
    // Observe each actual compiler invocation, then delegate unchanged to the
    // pre-resolved installed compiler. The executable and its verified output
    // still come from real Rust compilation, not a replacement success fixture.
    compiler_script(
        &bin,
        "printf '%s\\n' \"$PWD\" >> \"$RCH_NATIVE_PROBE_TEST_COMPILES\"\nexec \"$RCH_NATIVE_PROBE_TEST_RUSTC\" \"$@\"",
    );
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths).unwrap();
    let expected = serde_json::json!({
        "schema_version": 1,
        "probe": "rust_compile_run",
        "compiled": true,
        "executed": true,
        "output_verified": true,
    });
    for attempt in 0..2 {
        let output = Command::new(WORKER)
            .args(["runtime-probe", "--json"])
            .current_dir(directory.path())
            .env("PATH", &path)
            .env("TMPDIR", &temporary)
            .env("RCH_NATIVE_PROBE_TEST_COMPILES", &compilations)
            .env("RCH_NATIVE_PROBE_TEST_RUSTC", &rustc)
            .output()
            .unwrap();
        assert!(output.status.success(), "attempt {attempt}: {output:?}");
        assert!(output.stderr.is_empty(), "attempt {attempt}: {output:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            expected,
            "attempt {attempt} did not return one exact runtime receipt"
        );
    }
    let observed = std::fs::read_to_string(compilations).unwrap();
    let directories = observed.lines().map(PathBuf::from).collect::<Vec<_>>();
    assert_eq!(
        directories.len(),
        2,
        "each receipt requires a new compiler invocation"
    );
    assert_ne!(
        directories[0], directories[1],
        "a previous compile was reused"
    );
    for path in directories {
        assert!(
            path.starts_with(&temporary),
            "compile left its private temporary root: {}",
            path.display()
        );
    }
}

#[test]
fn native_runtime_probe_cli_refuses_missing_or_version_only_compilers() {
    let directory = fixture();
    let bin = directory.path().join("bin");
    let temporary = directory.path().join("temporary");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&temporary).unwrap();
    for version_only in [false, true] {
        if version_only {
            compiler_script(&bin, "printf 'rustc 1.100.0 version-only fixture\\n'");
        }
        let output = Command::new(WORKER)
            .args(["runtime-probe", "--json"])
            .current_dir(directory.path())
            .env("PATH", &bin)
            .env("TMPDIR", &temporary)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "version_only={version_only}: {output:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "failed probe emitted a success receipt: {output:?}"
        );
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let expected = if version_only {
            "did not produce an executable"
        } else {
            "spawn runtime compile command"
        };
        assert!(
            diagnostic.contains(expected),
            "version_only={version_only}: {diagnostic}"
        );
    }
}

#[test]
fn production_launch_and_timeout_restore_every_standard_descriptor_mask() {
    let directory = fixture();
    let witness = r#"
state=0
( : 3<&0 ) 2>/dev/null && state=$((state | 1))
( : 3>&1 ) 2>/dev/null && state=$((state | 2))
( : 3>&2 ) && state=$((state | 4))
printf '%s' "$state" > "$1"
"#;
    let script = format!(
        "{}\nuname() {{ printf Darwin; }}\n\
         mask=$1\n\
         if [ \"$((mask & 1))\" -ne 0 ]; then exec 0<&-; fi\n\
         if [ \"$((mask & 2))\" -ne 0 ]; then exec 1>&-; fi\n\
         if [ \"$((mask & 4))\" -ne 0 ]; then exec 2>&-; fi\n\
         if [ \"$2\" = setsid ]; then\n\
             rch_scope_launch_exec /bin/sh -c \"$3\" stdio-witness \"$4\"\n\
         else\n\
             rch_group_timeout --signal=KILL 2s /bin/sh -c \"$3\" stdio-witness \"$4\"\n\
         fi",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    for route in ["setsid", "timeout"] {
        for mask in 0_u8..=7 {
            let result = directory.path().join(format!("{route}-{mask}"));
            let output = Command::new("/bin/sh")
                .args(["-c", &script, "closed-stdio"])
                .arg(mask.to_string())
                .arg(route)
                .arg(witness)
                .arg(&result)
                .env_clear()
                .env("PATH", "")
                .env("RCH_WKR_BIN", WORKER)
                .output()
                .unwrap();
            assert!(output.status.success(), "{route} mask {mask}: {output:?}");
            assert!(output.stdout.is_empty(), "{route} mask {mask}: {output:?}");
            assert!(output.stderr.is_empty(), "{route} mask {mask}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(result).unwrap(),
                (7 ^ mask).to_string(),
                "{route} reopened a descriptor from original mask {mask}"
            );
        }
    }
}

#[test]
fn production_timeout_fallback_preserves_exit_two_and_refuses_missing_worker() {
    let run = |worker_path: &str| {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "{}\nrch_group_timeout --signal=KILL 2s /bin/sh -c 'printf reached; exit 2'",
                rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
            ))
            .env_clear()
            .env("PATH", "")
            .env("RCH_WKR_BIN", worker_path)
            .output()
            .unwrap()
    };
    let output = run(WORKER);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(output.stdout, b"reached");
    assert!(output.stderr.is_empty(), "{output:?}");

    let output = run("/no-such-rch-worker");
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        output.stderr.starts_with(b"RCH_SCOPED_LAUNCH_UNAVAILABLE:"),
        "{output:?}"
    );
}
