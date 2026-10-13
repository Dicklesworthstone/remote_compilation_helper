//! Clean-overlay transport inputs are never implicit compiler outputs.
//!
//! The broad C/C++ fallback deliberately includes new root-level executables.
//! Narrowing it to filename extensions breaks Make projects. Exclude only the
//! reserved immutable input instead; ordinary tar archives remain eligible.

/// Add the reserved source-archive exclusion to an implicit artifact policy.
///
/// An unanchored basename excludes the input at every depth, including inside
/// a broadly included build directory. Rsync emits these exclusions before
/// ordinary includes. Do not use this to rewrite an explicit native output
/// contract: its exact pattern list is part of the persisted admission proof.
pub(in crate::hook) fn exclude_source_archive(patterns: &mut Vec<String>) {
    const EXCLUDE: &str = "- .rch-clean-overlay-base.tar";
    if !patterns.iter().any(|pattern| pattern == EXCLUDE) {
        patterns.insert(0, EXCLUDE.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::artifact_patterns::{
        expected_output_glob_list, get_project_artifact_patterns,
        kind_has_enumerable_output_contract, kind_produces_transferable_artifacts,
    };
    use crate::transfer::{TransferPipeline, default_c_cpp_artifact_patterns};
    use rch_common::{CompilationKind, TransferConfig};
    use std::path::PathBuf;

    #[test]
    fn implicit_make_exclusion_preserves_the_complete_output_policy() {
        let original = default_c_cpp_artifact_patterns();
        let mut normalized = original.clone();
        exclude_source_archive(&mut normalized);
        exclude_source_archive(&mut normalized);
        assert_eq!(normalized.len(), original.len() + 1);
        assert_eq!(&normalized[1..], original.as_slice());
        assert_eq!(
            expected_output_glob_list(&normalized),
            expected_output_glob_list(&original)
        );
        for custom_target in [false, true] {
            assert_eq!(
                get_project_artifact_patterns(
                    Some(CompilationKind::Make),
                    Some("make all"),
                    custom_target,
                ),
                normalized
            );
        }
        assert!(kind_produces_transferable_artifacts(Some(
            CompilationKind::Make
        )));
        // A phony Make target may legitimately produce no files. The fix must
        // not turn Cargo's zero-output check into a new Make requirement.
        assert!(!kind_has_enumerable_output_contract(Some(
            CompilationKind::Make
        )));
    }

    #[test]
    fn staged_source_archives_are_not_publishable_even_from_an_old_collection() {
        // Match the reported RAM-backed caller on Linux without mutating the
        // process-global TMPDIR seen by unrelated parallel tests.
        #[cfg(target_os = "linux")]
        let root = tempfile::tempdir_in("/dev/shm").unwrap().keep();
        #[cfg(not(target_os = "linux"))]
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::write(root.join("source.c"), b"caller source sentinel\n").unwrap();
        let pipeline = TransferPipeline::new(
            root,
            "clean-overlay-policy".into(),
            "clean-overlay-policy-identity".into(),
            TransferConfig::default(),
        );
        let patterns =
            get_project_artifact_patterns(Some(CompilationKind::Make), Some("make all"), false);
        let outputs: Vec<PathBuf> = [
            "program",
            "a.out",
            "object.o",
            "libfixture.a",
            "libfixture.so.1",
            "program.exe",
            "distribution.tar",
            "build/result.json",
            "build/distribution.tar",
            "bin/program",
            "out/result",
            ".libs/libfixture.a",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let inputs: Vec<PathBuf> = [
            ".rch-clean-overlay-base.tar",
            "build/.rch-clean-overlay-base.tar",
            "build/nested/.rch-clean-overlay-base.tar",
            "source.c",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let mut candidates = outputs.clone();
        candidates.extend(inputs.clone());
        let (admitted, outside) = pipeline
            .partition_staged_artifact_paths(&candidates, &patterns)
            .unwrap();
        assert_eq!(admitted, outputs);
        assert_eq!(outside, inputs);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn clean_overlay_make_real_rsync_keeps_input_archives_on_the_worker() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        async fn run(mut command: Command) -> Vec<u8> {
            command.stdin(Stdio::null()).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(30), command.output())
                .await
                .expect("owned clean-overlay fixture timed out")
                .expect("git, make, a C compiler, ar, tar and rsync are required");
            assert!(
                output.status.success(),
                "fixture command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        }

        let root = tempfile::tempdir().unwrap().keep();
        let worker = root.join("worker project");
        let receiver = root.join("durable retrieval");
        std::fs::create_dir_all(&worker).unwrap();
        std::fs::create_dir_all(&receiver).unwrap();
        std::fs::write(worker.join("source.c"), b"int main(void) { return 0; }\n").unwrap();
        std::fs::write(
            worker.join("Makefile"),
            concat!(
                ".PHONY: all\nall:\n",
                "\t$(CC) -c source.c -o object.o\n",
                "\t$(AR) rcs libfixture.a object.o\n",
                "\t$(CC) source.c -o program\n",
                "\tmkdir -p build/nested bin out .libs\n",
                "\tcp program bin/program\n",
                "\tcp libfixture.a .libs/libfixture.a\n",
                "\tprintf 'verified\\n' > build/result.json\n",
                "\tprintf 'verified\\n' > out/result\n",
                "\ttar -cf distribution.tar program\n",
                "\tcp distribution.tar build/distribution.tar\n",
            ),
        )
        .unwrap();
        let mut init = Command::new("git");
        init.current_dir(&worker).args(["init", "-b", "main"]);
        run(init).await;
        let mut add = Command::new("git");
        add.current_dir(&worker)
            .args(["add", "source.c", "Makefile"]);
        run(add).await;
        let mut commit = Command::new("git");
        commit.current_dir(&worker).args([
            "-c",
            "user.name=RCH fixture",
            "-c",
            "user.email=rch-fixture@localhost",
            "commit",
            "-m",
            "owned clean-overlay fixture",
        ]);
        run(commit).await;
        let mut archive = Command::new("git");
        archive.current_dir(&worker).args([
            "archive",
            "--format=tar",
            "--output=.rch-clean-overlay-base.tar",
            "HEAD",
        ]);
        run(archive).await;
        let original_archive = std::fs::read(worker.join(".rch-clean-overlay-base.tar")).unwrap();
        let mut make = Command::new("make");
        make.current_dir(&worker).arg("all");
        run(make).await;
        for nested in ["build", "build/nested"] {
            std::fs::write(
                worker.join(nested).join(".rch-clean-overlay-base.tar"),
                &original_archive,
            )
            .unwrap();
        }
        let patterns =
            get_project_artifact_patterns(Some(CompilationKind::Make), Some("make all"), false);
        let mut copy = Command::new("rsync");
        copy.args([
            "-a",
            "--checksum",
            "--no-owner",
            "--no-group",
            "--safe-links",
        ]);
        for rule in crate::transfer::priority_rsync_includes(&patterns) {
            copy.arg(format!("--include={rule}"));
        }
        for pattern in &patterns {
            if let Some(exclude) = pattern.strip_prefix("- ") {
                copy.arg(format!("--exclude={exclude}"));
            }
        }
        copy.arg("--include=*/");
        for pattern in &patterns {
            if !pattern.starts_with("- ") {
                let include = pattern.strip_prefix("+ ").unwrap_or(pattern);
                copy.arg(format!("--include=/{include}"));
            }
        }
        copy.arg("--exclude=*")
            .arg(format!("{}/", worker.display()))
            .arg(format!("{}/", receiver.display()));
        run(copy).await;
        for relative in [
            "program",
            "object.o",
            "libfixture.a",
            "distribution.tar",
            "build/distribution.tar",
            "build/result.json",
            "bin/program",
            "out/result",
            ".libs/libfixture.a",
        ] {
            assert_eq!(
                std::fs::read(receiver.join(relative)).unwrap(),
                std::fs::read(worker.join(relative)).unwrap(),
                "legitimate Make output was not returned: {relative}"
            );
        }
        for relative in [
            ".rch-clean-overlay-base.tar",
            "build/.rch-clean-overlay-base.tar",
            "build/nested/.rch-clean-overlay-base.tar",
        ] {
            assert!(
                !receiver.join(relative).exists(),
                "input archive was staged: {relative}"
            );
            assert_eq!(
                std::fs::read(worker.join(relative)).unwrap(),
                original_archive
            );
        }
        let executable = Command::new(receiver.join("program"));
        run(executable).await;
    }
}
