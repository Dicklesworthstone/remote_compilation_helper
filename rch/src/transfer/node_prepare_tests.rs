//! Placement contracts plus subprocess coverage of the exact shipped wrapper.
use super::*;

fn pipeline(kind: CompilationKind, tracked: bool, platform: WorkerPlatform) -> TransferPipeline {
    let mut pipeline = TransferPipeline::new(
        PathBuf::from("/tmp/rch-node-preparation-contract"),
        "project".to_owned(),
        "source-hash".to_owned(),
        TransferConfig::default(),
    );
    pipeline.compilation_kind = Some(kind);
    pipeline.build_id = tracked.then_some(77);
    pipeline.worker_platform = platform;
    pipeline
}

#[test]
fn dependency_preparation_is_inside_the_tracked_workload() {
    let _guard = rch_common::test_guard!();
    for (kind, workload, runtime) in [
        (CompilationKind::Tsc, "tsc --noEmit", "node"),
        (CompilationKind::BunTest, "bun test", "bun"),
        (CompilationKind::BunTypecheck, "bun typecheck", "bun"),
    ] {
        let pipeline = pipeline(kind, true, WorkerPlatform::Posix);
        let command = pipeline.build_remote_command(workload, None);
        let session = command.find("setsid sh -c").expect("tracked process group");
        let preparation = command.find("rch-wkr prepare").expect("worker preparation");
        assert!(preparation > session);
        assert_eq!(command.matches("rch-wkr prepare").count(), 1);
        assert!(command.contains(&format!("rch-prepare {runtime} sh -c")));
        assert!(!command.contains("npm ci"));
        assert!(!command.contains("npm install"));
        assert!(!command.contains("bun install"));
    }
}

#[test]
fn untracked_and_windows_commands_still_require_preparation_success() {
    let _guard = rch_common::test_guard!();
    for platform in [WorkerPlatform::Posix, WorkerPlatform::Windows] {
        for kind in [
            CompilationKind::Tsc,
            CompilationKind::BunTest,
            CompilationKind::BunTypecheck,
        ] {
            let pipeline = pipeline(kind, false, platform);
            let command = pipeline.build_remote_command("compiler", None);
            assert_eq!(command.matches("rch-wkr prepare").count(), 1);
            assert!(!command.contains("setsid sh -c"));
        }
    }
}

#[test]
fn unrelated_command_payload_is_unchanged() {
    let _guard = rch_common::test_guard!();
    let original = "RUSTFLAGS='-C opt-level=2' cargo build --features 'a,b'";
    for kind in [
        CompilationKind::CargoBuild,
        CompilationKind::CargoTest,
        CompilationKind::GoTest,
        CompilationKind::NixBuild,
        CompilationKind::Job,
    ] {
        let pipeline = pipeline(kind, true, WorkerPlatform::Posix);
        assert_eq!(
            pipeline.wrap_with_dependency_preparation(original.to_owned()),
            original
        );
    }
}

#[test]
fn dependency_runtime_comes_from_the_kind_not_words_in_the_payload() {
    let _guard = rch_common::test_guard!();
    for (kind, runtime) in [
        (CompilationKind::Tsc, "node"),
        (CompilationKind::BunTest, "bun"),
        (CompilationKind::BunTypecheck, "bun"),
    ] {
        let pipeline = pipeline(kind, false, WorkerPlatform::Posix);
        let command = pipeline.wrap_with_dependency_preparation(
            "LABEL='node bun cargo' compiler 'literal ; payload'".to_owned(),
        );
        assert!(command.contains(&format!("rch-prepare {runtime} sh -c")));
    }
}

#[test]
#[cfg(unix)]
fn dependency_preparation_shell_protocol() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/node_prepare.py"
        ))
        .status()
        .expect("run preparation shell regressions (requires python3)");
    assert!(status.success(), "preparation shell regression failed");
}

#[cfg(unix)]
#[test]
fn rust_generated_wrapper_preserves_payload_and_preparation_failure() {
    let _guard = rch_common::test_guard!();
    for (kind, runtime, program, argument) in [
        (CompilationKind::Tsc, "node", "tsc", "--noEmit"),
        (CompilationKind::BunTest, "bun", "bun", "test"),
        (CompilationKind::BunTypecheck, "bun", "bun", "typecheck"),
    ] {
        for preparation_status in ["0", "2"] {
            check_generated_wrapper(kind, runtime, program, argument, preparation_status);
        }
    }
}

#[cfg(unix)]
fn check_generated_wrapper(
    kind: CompilationKind,
    runtime: &str,
    program: &str,
    argument: &str,
    preparation_status: &str,
) {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().unwrap();
    let project = fixture.path().join("project with ' quotes");
    let tools = fixture.path().join("worker-tools");
    let local = project.join("node_modules/.bin");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(project.join("package.json"), "{}").unwrap();
    let write_tool = |path: &Path, source: &str| {
        std::fs::write(path, source).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    };
    write_tool(
        &tools.join("rch-wkr"),
        "#!/bin/sh\nset -eu\n\
         [ \"$*\" = \"prepare --project . --runtime $EXPECTED_RUNTIME\" ] || exit 91\n\
         printf 'prepared\\n' >> events\n\
         if IFS= read -r ignored; then exit 92; fi\n\
         printf 'preparation metadata\\n'\n\
         exit \"$PREPARATION_STATUS\"\n",
    );
    write_tool(&tools.join(program), "#!/bin/sh\nexit 96\n");
    write_tool(
        &local.join(program),
        "#!/bin/sh\nprintf 'compiled\\n' >> events\n\
         printf '[%s]\\n' \"$@\"\nexit 23\n",
    );
    let pipeline = pipeline(kind, false, WorkerPlatform::Posix);
    let command = pipeline.wrap_with_dependency_preparation(format!(
        "{program} {argument} 'literal $value; not shell code'"
    ));
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", &command])
        .current_dir(&project)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("PREPARATION_STATUS", preparation_status)
        .env("EXPECTED_RUNTIME", runtime)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let events = std::fs::read_to_string(project.join("events")).unwrap();
    if preparation_status == "0" {
        assert_eq!(output.status.code(), Some(23));
        assert_eq!(events, "prepared\ncompiled\n");
        assert_eq!(
            output.stdout,
            format!("[{argument}]\n[literal $value; not shell code]\n").as_bytes()
        );
        assert_eq!(output.stderr, b"preparation metadata\n");
    } else {
        assert_eq!(output.status.code(), Some(121));
        assert_eq!(events, "prepared\n");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("the command was not run"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn source_refresh_preserves_only_worker_owned_dependency_state() {
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    let remote = fixture.path().join("worker");
    for directory in [&source, &remote] {
        std::fs::create_dir_all(directory.join("node_modules/.bin")).unwrap();
        std::fs::create_dir_all(directory.join(".rch_prepare_logs")).unwrap();
    }
    std::fs::write(source.join("package.json"), "manifest-v1").unwrap();
    std::fs::write(source.join("bun.lock"), "selected-lock").unwrap();
    std::fs::write(remote.join("obsolete-source"), "must be removed").unwrap();
    for name in [
        "node_modules/.bin/compiler",
        ".rch_dep_fingerprint.json",
        ".rch_dep_fingerprint.json.tmp",
        ".rch_prepare_logs/install.log",
    ] {
        std::fs::write(source.join(name), "dispatcher-only bytes").unwrap();
        std::fs::write(remote.join(name), "worker-only bytes").unwrap();
    }
    let mut config = TransferConfig::default();
    config.exclude_patterns.clear();
    let mut pipeline =
        TransferPipeline::new(source.clone(), "project".into(), "hash".into(), config);
    let excludes = pipeline.get_effective_excludes();
    for (index, manifest) in ["manifest-v1", "manifest-v2", "manifest-v3"]
        .iter()
        .enumerate()
    {
        if index > 0 {
            pipeline.sync_include_patterns = Some(vec!["*/".into(), "*".into()]);
        }
        if index == 2 {
            for name in [
                "node_modules",
                ".rch_dep_fingerprint.json",
                ".rch_dep_fingerprint.json.tmp",
                ".rch_prepare_logs",
            ] {
                std::fs::rename(source.join(name), fixture.path().join(name)).unwrap();
            }
        }
        std::fs::write(source.join("package.json"), manifest).unwrap();
        let mut sync = tokio::process::Command::new("rsync");
        sync.args(["-a", "--checksum", "--delete"]);
        pipeline.append_sync_filter_args(&mut sync, &excludes);
        let result = sync
            .arg(format!("{}/", source.display()))
            .arg(format!("{}/", remote.display()))
            .output()
            .await
            .expect("run native dependency-state transfer regression (requires rsync)");
        assert!(result.status.success(), "{:?}", result);
        assert_eq!(
            std::fs::read(remote.join("package.json")).unwrap(),
            manifest.as_bytes()
        );
        assert_eq!(
            std::fs::read(remote.join("bun.lock")).unwrap(),
            b"selected-lock"
        );
        for name in [
            "node_modules/.bin/compiler",
            ".rch_dep_fingerprint.json",
            ".rch_dep_fingerprint.json.tmp",
            ".rch_prepare_logs/install.log",
        ] {
            assert_eq!(
                std::fs::read(remote.join(name)).unwrap(),
                b"worker-only bytes",
                "{name}"
            );
        }
        assert!(!remote.join("obsolete-source").exists());
    }
}
