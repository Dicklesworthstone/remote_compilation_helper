//! Projects aliases translate paths; they are not a build's source ownership.
//!
//! Initialize the namespace under the existing registry metadata mutex BEFORE
//! persisting a job intent or acquiring a source/pair guard. That transaction
//! checks unfinished lexical and physical owners but never writes a source
//! claim. Existing source claims, including legacy broad ones, remain immutable.

use super::super::ssh::{
    RemoteSourceAuthorityLock, acquire_remote_source_authority_lock,
    canonical_source_authority_root, run_offload_ssh_command_with_stdin,
    validate_source_authority_intent,
};
use super::{PathTopologyPolicy, SyncClosurePlanEntry, WorkerConfig};
use anyhow::Context as _;
use sha2::{Digest as _, Sha256};
use std::time::Duration;

const REGISTRY: &str = "/tmp/rch-source-authority-locks/claims-v1";
const PATHS: &str = include_str!("source_namespace_paths.sh");
const ADMISSION: &str = include_str!("source_claim_admission.sh");
const CLAIMS: &str = include_str!("source_claim_registry.sh");
const CONTROL: &str = include_str!("source_namespace_control.sh");
const SOURCE_ADMISSION_WAIT: Duration = Duration::from_secs(60);

fn retryable_source_admission_error(error: &anyhow::Error) -> bool {
    let detail = format!("{error:#}");
    detail.contains("RCH: durable source ownership: unfinished overlapping source owner")
        || detail
            .contains("RCH: durable source ownership: unfinished overlapping physical source owner")
}

/// A single eligible worker should wait briefly for a completed predecessor
/// to retire instead of failing the remote-only command immediately. Retry only
/// the two explicit pre-grant overlap verdicts. Every failed acquisition drops
/// its remote holder before this function waits, so exact-owner recovery can
/// still reacquire the source locks and finish retirement (#105).
pub(super) async fn acquire_source_authority_with_retry(
    worker: &WorkerConfig,
    roots: &[String],
    mut source_pair: Option<&mut RemoteSourceAuthorityLock>,
    identity: &str,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    let deadline = tokio::time::Instant::now() + wait_timeout.min(SOURCE_ADMISSION_WAIT);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow::Error::new(crate::transfer::SourceAuthorityBusy(
                format!(
                    "timed out waiting for overlapping source ownership on {}",
                    worker.id
                ),
            )));
        }
        match acquire_remote_source_authority_lock(
            worker,
            roots,
            source_pair.as_deref_mut(),
            identity,
            remaining,
        )
        .await
        {
            Ok(guard) => return Ok(guard),
            Err(error)
                if retryable_source_admission_error(&error)
                    && tokio::time::Instant::now() < deadline =>
            {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(overlapping_owner_outlived_wait(error, worker));
                }
                tokio::time::sleep(Duration::from_secs(1).min(remaining)).await;
            }
            Err(error) if retryable_source_admission_error(&error) => {
                return Err(overlapping_owner_outlived_wait(error, worker));
            }
            Err(error) => return Err(error),
        }
    }
}

/// An overlapping owner that never retired within the admission wait keeps
/// this worker's source as surely as a held lock (bd-p3kuz).
fn overlapping_owner_outlived_wait(error: anyhow::Error, worker: &WorkerConfig) -> anyhow::Error {
    error.context(crate::transfer::SourceAuthorityBusy(format!(
        "overlapping source owner on {} did not retire within the admission wait",
        worker.id
    )))
}

/// The only durable roots are actual sync destinations and exact auxiliary
/// trees this job mutates. Deliberately accept no topology policy here. A base
/// that is genuinely selected as a repository is NOT filtered or narrowed.
pub(super) fn build_source_roots(
    plan: &[SyncClosurePlanEntry],
    pair_source: Option<&str>,
    retained_source: Option<&str>,
    freshness_control: Option<&str>,
    target: Option<&str>,
) -> Vec<String> {
    let mut roots = plan
        .iter()
        .map(|entry| entry.remote_root.as_str())
        .chain(
            [pair_source, retained_source, freshness_control, target]
                .into_iter()
                .flatten(),
        )
        .map(canonical_source_authority_root)
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn namespace_command(
    policy: &PathTopologyPolicy,
    identity: &str,
    registry: &str,
) -> anyhow::Result<String> {
    let canonical = policy
        .canonical_root()
        .to_str()
        .context("worker canonical topology root is not UTF-8")?;
    let alias = policy
        .alias_root()
        .to_str()
        .context("worker alias topology root is not UTF-8")?;
    let canonical = canonical_source_authority_root(canonical);
    let alias = canonical_source_authority_root(alias);
    let mut roots = vec![canonical.clone(), alias.clone()];
    roots.sort();
    roots.dedup();
    validate_source_authority_intent(&roots, identity)?;
    let body = format!("{}\n", roots.join("\n"));
    let digest = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let paths = |mode: &str| {
        format!(
            "set -- {mode} {} {}\n{PATHS}",
            quote(&canonical),
            quote(&alias),
        )
    };
    let registry_script = format!(
        "{}\n{CLAIMS}",
        rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
    );
    // Match ssh.rs's registry layout. No source, pair or activity descriptors
    // exist in this parent. Every attempt drops its metadata flock before the
    // bounded wait, allowing exact-owner recovery to release the old claim.
    Ok(format!(
        "set -eu\numask 077\nregistry={registry}\n\
         [ ! -L \"$registry\" ]\nmkdir -p -- \"$registry\"\n\
         for directory in \"$registry/released\" \"$registry/cancelled\" \"$registry/quarantine\"; do\n\
         [ ! -L \"$directory\" ]\nmkdir -p -- \"$directory\"\ndone\n\
         [ ! -L \"$registry/metadata.lock\" ]\nsync -f \"$registry\"\n\
         rch_source_attempt() {{ (\nset -eu\n\
         exec flock -x -- \"$registry/metadata.lock\" sh -c {script} \
         rch-source-namespace \"$registry\" {identity} {digest} topology {check} {create} \
         <<'RCH_NAMESPACE_SCOPE'\n{body}RCH_NAMESPACE_SCOPE\n\
         ); }}\nrch_admission_attempts=6\n{ADMISSION}",
        registry = quote(registry),
        script = quote(&registry_script),
        identity = quote(identity),
        check = quote(&paths("check")),
        create = quote(&paths("create")),
    ))
}

pub(super) async fn initialize_worker_namespace(
    worker: &WorkerConfig,
    policy: &PathTopologyPolicy,
    identity: &str,
) -> anyhow::Result<()> {
    let script = namespace_command(policy, identity, REGISTRY)?;
    // Bound the worker as well as the SSH client. Killing only the local SSH
    // process can leave a queued initializer or a pipe-holding descendant on
    // the worker, retaining the registry mutex after this future has failed.
    // CONTROL owns only pre-intent namespace setup, never a source/build grant.
    let output = run_offload_ssh_command_with_stdin(
        worker,
        CONTROL,
        script.as_bytes(),
        Duration::from_secs(20),
    )
    .await?;
    anyhow::ensure!(
        output.status.success() && output.stdout.as_slice() == b"RCH_TOPOLOGY_OK\n",
        "worker source namespace initialization refused on {} (status {:?}): {}",
        worker.id,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::SyncClosureMode;
    use super::*;
    use std::path::PathBuf;

    fn root(path: &str) -> SyncClosurePlanEntry {
        SyncClosurePlanEntry {
            local_root: PathBuf::from(path),
            project_id: "test".to_owned(),
            root_hash: "test".to_owned(),
            remote_root: path.to_owned(),
            is_primary: true,
            mode: SyncClosureMode::Full,
        }
    }

    #[test]
    fn source_namespace_bases_are_not_inferred_as_owned_roots() {
        let roots = build_source_roots(
            &[root("/projects/a"), root("/projects/dependency")],
            None,
            None,
            None,
            Some("/pools/a"),
        );
        assert_eq!(roots, ["/pools/a", "/projects/a", "/projects/dependency"]);
        let sibling = build_source_roots(&[root("/projects/b")], None, None, None, None);
        assert_eq!(sibling, ["/projects/b"]);
    }

    #[test]
    fn source_namespace_keeps_pair_retention_freshness_and_shared_targets() {
        let roots = build_source_roots(
            &[root("/staging/pair/repo"), root("/staging/pair/dep")],
            Some("/staging/pair"),
            Some("/staging/pair.retained-job"),
            Some("/staging/pair.freshness"),
            Some("/pools/shared"),
        );
        assert_eq!(
            roots,
            [
                "/pools/shared",
                "/staging/pair",
                "/staging/pair.freshness",
                "/staging/pair.retained-job",
                "/staging/pair/dep",
                "/staging/pair/repo",
            ]
        );
    }

    #[test]
    fn source_namespace_never_filters_a_genuinely_selected_base_or_dependency() {
        let roots = build_source_roots(
            &[
                root("/projects/"),
                root("/projects/repo"),
                root("/projects/repo/"),
            ],
            None,
            None,
            None,
            Some("/projects/repo/.rch-target"),
        );
        assert_eq!(
            roots,
            ["/projects", "/projects/repo", "/projects/repo/.rch-target"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_namespace_production_command_initializes_without_a_claim() {
        use std::io::Write as _;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let canonical = temp.path().join("projects with ' quotes");
        let alias = temp.path().join("alias");
        let registry = temp.path().join("registry");
        let policy = PathTopologyPolicy::new(canonical.clone(), alias.clone());
        let command = namespace_command(&policy, "0123", registry.to_str().unwrap()).unwrap();
        for _ in 0..2 {
            let mut child = std::process::Command::new("sh")
                .args(["-c", CONTROL])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(command.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"RCH_TOPOLOGY_OK\n");
            assert_eq!(std::fs::canonicalize(&alias).unwrap(), canonical);
            assert!(std::fs::read_dir(&registry).unwrap().all(|entry| {
                let path = entry.unwrap().path();
                !matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("claim" | "pending")
                )
            }));
        }
    }

    #[test]
    fn source_admission_retry_classifier_is_narrow() {
        let lexical = anyhow::anyhow!(
            "source-authority lock exited; stderr=RCH: durable source ownership: unfinished overlapping source owner"
        );
        let physical = anyhow::anyhow!(
            "source-authority lock exited; stderr=RCH: durable source ownership: unfinished overlapping physical source owner"
        );
        assert!(retryable_source_admission_error(&lexical));
        assert!(retryable_source_admission_error(&physical));

        for terminal in [
            "RCH: durable source ownership: invalid claim record",
            "RCH: durable source ownership: source intent cancelled",
            "RCH: durable source ownership: source identity already claimed",
            "SSH command timed out",
        ] {
            assert!(!retryable_source_admission_error(&anyhow::anyhow!(
                "{terminal}"
            )));
        }
    }

    #[test]
    fn source_namespace_rejects_bad_intents_before_remote_setup() {
        let policy = PathTopologyPolicy::new("/projects".into(), "/dp".into());
        assert!(namespace_command(&policy, "not-a-token", REGISTRY).is_err());
        let bad = PathTopologyPolicy::new("/projects\n/injected".into(), "/dp".into());
        assert!(namespace_command(&bad, "0123", REGISTRY).is_err());
    }
}
