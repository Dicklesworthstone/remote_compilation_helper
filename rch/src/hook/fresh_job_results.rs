//! Explicit fresh-output preparation for ordinary remote jobs.
//!
//! Source authority and the durable recovery recipe belong to the caller.
//! Preparation retains old bytes; it never deletes them or replays a payload.

use super::*;
use rch_common::job_results::{
    JobResultsPreparationRequest, JobResultsPreparationResponse, SCHEMA_VERSION,
    retention_root_for, validate_result_dirs,
};

const PREPARATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preparation {
    pub request: JobResultsPreparationRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<JobResultsPreparationResponse>,
}

pub(super) fn validate_directories(directories: &[PathBuf]) -> anyhow::Result<()> {
    let directories = directories
        .iter()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .context("fresh result directory is not UTF-8")
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    validate_result_dirs(&directories).map_err(anyhow::Error::msg)
}

/// Translate invocation-relative outputs for each upload root. Wider source
/// uploads must preserve them too, while a selected source root inside an
/// output is a contradictory contract, not a reason to silently omit source.
pub(super) fn protected_upload_dirs(
    invocation_root: &Path,
    directories: &[PathBuf],
    upload_root: &Path,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut protected = Vec::new();
    for directory in directories {
        let output = invocation_root.join(directory);
        anyhow::ensure!(
            !upload_root.starts_with(&output),
            "fresh result directory {} contains an admitted source root {}",
            output.display(),
            upload_root.display()
        );
        if let Ok(relative) = output.strip_prefix(upload_root) {
            protected.push(relative.to_owned());
        }
    }
    Ok(protected)
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    configure_clean_git_command(&mut command);
    command
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn validate_output_ancestor(
    root: &Path,
    ancestor: &Path,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    // An index lookup checks exactly this path, unlike ls-files on a parent
    // directory. A gitlink or tracked symlink is an indexed entry whose
    // descendants ls-files in the enclosing repository will not report.
    let index_path = format!(":./{}", ancestor.display());
    let status = tokio::time::timeout_at(
        deadline,
        git_command(root)
            .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
            .arg(index_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await
    .context("fresh result indexed-ancestor check timed out")??;
    match status.code() {
        Some(1) => {}
        Some(0) => anyhow::bail!(
            "fresh result directory contains tracked source or descends from an indexed source entry: {}",
            ancestor.display()
        ),
        _ => anyhow::bail!(
            "could not verify tracked-source protection for fresh result ancestor {}",
            ancestor.display()
        ),
    }

    let path = root.join(ancestor);
    let metadata = tokio::time::timeout_at(deadline, tokio::fs::symlink_metadata(&path))
        .await
        .context("fresh result local-path check timed out")?;
    match metadata {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "fresh result directory has a symlink ancestor: {}",
                ancestor.display()
            );
            anyhow::ensure!(
                metadata.is_dir(),
                "fresh result directory has a non-directory ancestor: {}",
                ancestor.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect fresh result ancestor {}", ancestor.display()));
        }
    }
    let nested_git =
        tokio::time::timeout_at(deadline, tokio::fs::symlink_metadata(path.join(".git")))
            .await
            .context("fresh result nested-repository check timed out")?;
    match nested_git {
        Ok(_) => anyhow::bail!(
            "fresh result directory would move source in a nested Git repository: {}",
            ancestor.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect nested Git marker below {}", ancestor.display())),
    }
}

/// Protect each declared root and its ancestry from indexed source, links and
/// nested repositories. Contents of a declared generated root are not scanned:
/// mutation tools may place copied checkouts inside their retained output.
/// Check roots independently: `ls-files --error-unmatch` with several paths
/// returns 1 when ANY path is untracked, even if another contains tracked files.
pub(super) async fn validate_local_sources(
    root: &Path,
    directories: &[PathBuf],
) -> anyhow::Result<()> {
    validate_directories(directories)?;
    let deadline = tokio::time::Instant::now() + PREPARATION_TIMEOUT;
    let inside = tokio::time::timeout_at(
        deadline,
        git_command(root)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output(),
    )
    .await
    .context("fresh result source validation timed out")??;
    anyhow::ensure!(
        inside.status.success() && inside.stdout == b"true\n",
        "--fresh-result-dirs requires a Git working tree to protect tracked source"
    );
    let mut checked_ancestors = std::collections::BTreeSet::new();
    for directory in directories {
        let mut ancestor = PathBuf::new();
        for component in directory.components() {
            ancestor.push(component);
            if checked_ancestors.insert(ancestor.clone()) {
                validate_output_ancestor(root, &ancestor, deadline).await?;
            }
        }
        // The status alone is authoritative here. Discard potentially large
        // tracked listings and the expected untracked-path diagnostic.
        let status = tokio::time::timeout_at(
            deadline,
            git_command(root)
                .args(["ls-files", "--error-unmatch", "--"])
                .arg(directory)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await
        .context("fresh result tracked-source check timed out")??;
        match status.code() {
            Some(1) => {}
            Some(0) => anyhow::bail!(
                "fresh result directory contains tracked source: {}; choose an output-only directory",
                directory.display()
            ),
            _ => anyhow::bail!(
                "could not verify tracked-source protection for fresh result directory {}",
                directory.display()
            ),
        }
    }
    Ok(())
}

/// Anchor retention beside the complete uploaded source root, including jobs
/// invoked from a nested directory. The sibling is separately source-granted.
pub(super) fn request(
    source_root: &str,
    invocation_root: &str,
    directories: &[PathBuf],
) -> anyhow::Result<JobResultsPreparationRequest> {
    validate_directories(directories)?;
    let invocation = Path::new(invocation_root)
        .strip_prefix(source_root)
        .context("fresh result invocation escaped the uploaded source root")?;
    let plan_id = uuid::Uuid::new_v4().simple().to_string();
    let request = JobResultsPreparationRequest {
        schema_version: SCHEMA_VERSION,
        retention_root: retention_root_for(source_root, &plan_id).map_err(anyhow::Error::msg)?,
        plan_id,
        source_root: source_root.to_owned(),
        result_dirs: directories
            .iter()
            .map(|directory| {
                invocation
                    .join(directory)
                    .to_str()
                    .map(str::to_owned)
                    .context("fresh result directory is not UTF-8")
            })
            .collect::<anyhow::Result<_>>()?,
    };
    request.validate().map_err(anyhow::Error::msg)?;
    Ok(request)
}

fn preparation_script(
    request: &JobResultsPreparationRequest,
    source_identity: &str,
) -> anyhow::Result<String> {
    request.validate().map_err(anyhow::Error::msg)?;
    let bytes = serde_json::to_string(request)?;
    // JSON escapes embedded newlines; neither a path nor an argument can close
    // this literal, single-line payload. The enclosing finite RPC acquires
    // source activity only after the entire program has arrived.
    let script = format!(
        "{}\nrch_wkr_locate || {{ echo 'RCH: fresh results require a native rch-wkr' >&2; exit 73; }}\nexec \"$RCH_WKR\" prepare-job-results <<'RCH_FRESH_JOB_RESULTS_JSON'\n{bytes}\nRCH_FRESH_JOB_RESULTS_JSON\n",
        rch_common::wkr_locate::WKR_LOCATE_SHELL
    );
    Ok(crate::transfer::source_activity_bounded_script(
        &super::ssh::source_authority_activity_prefix(source_identity)?,
        &script,
        PREPARATION_TIMEOUT,
    ))
}

pub(super) async fn prepare(
    worker: &WorkerConfig,
    request: &JobResultsPreparationRequest,
    source_identity: &str,
) -> anyhow::Result<JobResultsPreparationResponse> {
    let script = preparation_script(request, source_identity)?;
    let output = super::ssh::run_offload_ssh_command_with_stdin(
        worker,
        "sh -s",
        script.as_bytes(),
        PREPARATION_TIMEOUT,
    )
    .await
    .with_context(|| {
        format!(
            "fresh result preparation was not confirmed; inspect retained intent at {} and recover this job without replaying it",
            request.retention_root
        )
    })?;
    anyhow::ensure!(
        output.status.success(),
        "fresh result preparation refused before job execution; retained intent: {}; worker: {}",
        request.retention_root,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let response: JobResultsPreparationResponse = serde_json::from_slice(&output.stdout)
        .context("worker did not return a complete fresh result preparation receipt")?;
    response.validate_for(request).map_err(anyhow::Error::msg)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_job_results_protect_outputs_in_primary_and_enclosing_uploads() {
        let invocation = Path::new("/projects/repo/package");
        let directories = vec![PathBuf::from("reports"), PathBuf::from("out/shards")];
        for (root, expected) in [
            ("/projects/repo/package", vec!["reports", "out/shards"]),
            (
                "/projects/repo",
                vec!["package/reports", "package/out/shards"],
            ),
            (
                "/projects",
                vec!["repo/package/reports", "repo/package/out/shards"],
            ),
            ("/projects/dependency", Vec::new()),
        ] {
            assert_eq!(
                protected_upload_dirs(invocation, &directories, Path::new(root)).unwrap(),
                expected.into_iter().map(PathBuf::from).collect::<Vec<_>>()
            );
        }
        for root in [
            "/projects/repo/package/reports",
            "/projects/repo/package/out/shards/copied-source",
        ] {
            assert!(protected_upload_dirs(invocation, &directories, Path::new(root)).is_err());
        }
    }

    #[tokio::test]
    async fn fresh_job_results_protect_tracked_sources_in_any_declared_directory() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        assert!(
            git_command(root)
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::create_dir_all(root.join("reports")).unwrap();
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        std::fs::write(root.join("reports/old.json"), "old report").unwrap();
        std::fs::write(root.join("src/nested/source.rs"), "tracked source").unwrap();
        assert!(
            git_command(root)
                .args(["add", "src"])
                .status()
                .await
                .unwrap()
                .success()
        );
        validate_local_sources(root, &[PathBuf::from("reports")])
            .await
            .unwrap();
        for directories in [
            vec![PathBuf::from("reports"), PathBuf::from("src")],
            vec![PathBuf::from("src"), PathBuf::from("reports")],
            vec![PathBuf::from("src/nested")],
        ] {
            assert!(
                validate_local_sources(root, &directories)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("tracked source")
            );
        }
        assert_eq!(
            std::fs::read_to_string(root.join("src/nested/source.rs")).unwrap(),
            "tracked source"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("reports/old.json")).unwrap(),
            "old report"
        );
    }

    #[tokio::test]
    async fn fresh_job_results_refuse_unverifiable_source_and_literal_metacharacters() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        assert!(
            validate_local_sources(root, &[PathBuf::from("out")])
                .await
                .is_err()
        );
        assert!(
            git_command(root)
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::write(root.join("source.rs"), "source").unwrap();
        assert!(
            git_command(root)
                .args(["add", "source.rs"])
                .status()
                .await
                .unwrap()
                .success()
        );
        // A literal '*' result name must not match every tracked input.
        validate_local_sources(root, &[PathBuf::from("*")])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_job_results_refuse_indexed_gitlink_descendants_from_nested_invocations() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        assert!(
            git_command(root)
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(
            git_command(root)
                .args([
                    "-c",
                    "user.name=RCH Test",
                    "-c",
                    "user.email=rch-test@example.invalid",
                    "commit",
                    "--allow-empty",
                    "--no-gpg-sign",
                    "-qm",
                    "source fixture",
                ])
                .status()
                .await
                .unwrap()
                .success()
        );
        let revision = git_command(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .await
            .unwrap();
        assert!(revision.status.success());
        let revision = std::str::from_utf8(&revision.stdout).unwrap().trim();
        std::fs::create_dir_all(root.join("vendor/dep/src")).unwrap();
        std::fs::write(root.join("vendor/dep/src/lib.rs"), "submodule source").unwrap();
        assert!(
            git_command(root)
                .args(["update-index", "--add", "--cacheinfo"])
                .arg(format!("160000,{revision},vendor/dep"))
                .status()
                .await
                .unwrap()
                .success()
        );
        // The outer repository does not list descendants of its gitlink. This
        // is the hole that the exact-index ancestor check must close.
        assert_eq!(
            git_command(root)
                .args(["ls-files", "--error-unmatch", "--", "vendor/dep/src"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .unwrap()
                .code(),
            Some(1)
        );
        for directory in ["vendor/dep", "vendor/dep/src", "vendor/dep/new-output"] {
            assert!(
                validate_local_sources(root, &[PathBuf::from(directory)])
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("indexed source entry")
            );
        }
        assert!(
            validate_local_sources(&root.join("vendor"), &[PathBuf::from("dep/src")])
                .await
                .unwrap_err()
                .to_string()
                .contains("indexed source entry")
        );
        assert_eq!(
            std::fs::read_to_string(root.join("vendor/dep/src/lib.rs")).unwrap(),
            "submodule source"
        );
    }

    #[tokio::test]
    async fn fresh_job_results_refuse_symlinks_and_selected_nested_repository_roots() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        assert!(
            git_command(root)
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::create_dir_all(root.join("nested/src")).unwrap();
        assert!(
            git_command(&root.join("nested"))
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::write(root.join("nested/src/lib.rs"), "nested source").unwrap();
        assert!(
            git_command(&root.join("nested"))
                .args(["add", "src/lib.rs"])
                .status()
                .await
                .unwrap()
                .success()
        );
        for directory in ["nested", "nested/src", "nested/output"] {
            assert!(
                validate_local_sources(root, &[PathBuf::from(directory)])
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("nested Git repository")
            );
        }
        symlink("nested", root.join("alias")).unwrap();
        for directory in ["alias", "alias/output"] {
            assert!(
                validate_local_sources(root, &[PathBuf::from(directory)])
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("symlink ancestor")
            );
        }
        symlink("nested", root.join("indexed-alias")).unwrap();
        assert!(
            git_command(root)
                .args(["add", "indexed-alias"])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(
            validate_local_sources(root, &[PathBuf::from("indexed-alias/output")])
                .await
                .unwrap_err()
                .to_string()
                .contains("indexed source entry")
        );
    }

    #[tokio::test]
    async fn fresh_job_results_allow_generated_roots_below_shared_source_parents() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        assert!(
            git_command(root)
                .args(["init", "-q"])
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::create_dir_all(root.join("shared/generated/copied/.git")).unwrap();
        std::fs::write(root.join("shared/source.rs"), "tracked source").unwrap();
        std::fs::write(
            root.join("shared/generated/copied/source.rs"),
            "generated mutation checkout",
        )
        .unwrap();
        assert!(
            git_command(root)
                .args(["add", "shared/source.rs"])
                .status()
                .await
                .unwrap()
                .success()
        );
        validate_local_sources(root, &[PathBuf::from("shared/generated")])
            .await
            .unwrap();
        validate_local_sources(&root.join("shared"), &[PathBuf::from("generated")])
            .await
            .unwrap();
        assert!(
            validate_local_sources(root, &[PathBuf::from("shared")])
                .await
                .unwrap_err()
                .to_string()
                .contains("tracked source")
        );
    }

    #[test]
    fn fresh_job_results_plan_binds_nested_invocation_and_literal_payload() {
        let plan = request(
            "/worker/project",
            "/worker/project/tools/gate",
            &[PathBuf::from("reports/current run")],
        )
        .unwrap();
        assert_eq!(plan.result_dirs, ["tools/gate/reports/current run"]);
        assert!(
            plan.retention_root
                .starts_with("/worker/project.rch-job-results-")
        );
        assert!(request("/worker/project", "/worker/other", &[PathBuf::from("out")]).is_err());
        let script = preparation_script(&plan, "ab12").unwrap();
        assert!(script.contains("prepare-job-results"));
        assert!(script.contains("--rch-finite-rpc"));
        assert!(script.contains(&serde_json::to_string(&plan).unwrap()));
    }
}
