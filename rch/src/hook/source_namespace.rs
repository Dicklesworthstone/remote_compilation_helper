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
use rch_common::WorkerId;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::time::Duration;

const REGISTRY: &str = "/var/tmp/rch-source-authority-locks/claims-v1";
const PATHS: &str = include_str!("source_namespace_paths.sh");
const ADMISSION: &str = include_str!("source_claim_admission.sh");
const CLAIMS: &str = include_str!("source_claim_registry.sh");
const CONTROL: &str = include_str!("source_namespace_control.sh");
const SOURCE_ADMISSION_WAIT: Duration = Duration::from_secs(60);

/// A completed namespace verdict proved that this worker's existing physical
/// roots cannot satisfy the requested topology. Another worker may serve the
/// job, but repeating it on this worker cannot repair its filesystem layout.
#[derive(Debug, Clone)]
pub(in crate::hook) struct SourceTopologyIncompatible {
    pub(in crate::hook) worker_id: WorkerId,
    pub(in crate::hook) mismatch: rch_common::SourceTopologyMismatch,
}

impl SourceTopologyIncompatible {
    pub(in crate::hook) fn mismatch(&self) -> &rch_common::SourceTopologyMismatch {
        &self.mismatch
    }
}

impl std::fmt::Display for SourceTopologyIncompatible {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "worker {} has incompatible source topology (canonical {:?}, alias {:?}): {}; \
             choose a worker with a compatible layout or have the operator correct the configured \
             mapping; existing directories and aliases will not be overwritten",
            self.worker_id,
            self.mismatch.topology.canonical_root,
            self.mismatch.topology.alias_root,
            self.mismatch.detail,
        )
    }
}

impl std::error::Error for SourceTopologyIncompatible {}

/// Only the path program's finite metadata belongs in a permanent worker
/// report. SSH startup banners or unrelated stderr may contain source data.
fn topology_refusal_detail(
    verdict: &str,
    stderr: &str,
    requested: &rch_common::SourceTopology,
) -> String {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PhysicalMapping {
        canonical: String,
        canonical_physical: String,
        alias: String,
        alias_physical: String,
    }

    let physical_path = |path: &str| {
        (path.starts_with('/') || path == "<unresolved>") && !path.contains(['\0', '\n', '\r'])
    };
    let mut mappings = stderr.lines().filter_map(|line| {
        let mapping: PhysicalMapping =
            serde_json::from_str(line.strip_prefix("RCH_SOURCE_TOPOLOGY_PATHS ")?).ok()?;
        (mapping.canonical == requested.canonical_root
            && mapping.alias == requested.alias_root
            && physical_path(&mapping.canonical_physical)
            && physical_path(&mapping.alias_physical))
        .then_some(mapping)
    });
    let first = mappings.next();
    let Some(mapping) = first.filter(|_| mappings.next().is_none()) else {
        return format!(
            "{verdict}; physical mapping metadata unavailable or did not match the requested roots"
        );
    };
    // Reserve space for both physical roots. One unusually long path must
    // not remove the other mapping or introduce raw terminal controls.
    let path_metadata = |value: &str| {
        let escaped = format!("{value:?}");
        if escaped.len() <= 1792 {
            return escaped;
        }
        let mut bounded = String::new();
        for character in escaped.chars() {
            if bounded.len() + character.len_utf8() > 1792 {
                break;
            }
            bounded.push(character);
        }
        bounded.push_str(" [truncated]");
        bounded
    };
    format!(
        "{verdict}; canonical_physical={}; alias_physical={}",
        path_metadata(&mapping.canonical_physical),
        path_metadata(&mapping.alias_physical),
    )
}

// A bounded, monotonic wait reports metadata contention independently of the
// enclosing control group's 15-second execution deadline. Python is already
// required for the registry's record/directory fsync. The descriptor survives
// exec and CONTROL kills every inheriting descendant before acknowledgement.
const REGISTRY_LOCK: &str = r#"
import errno, fcntl, math, os, stat, sys, time
try:
    timing_scale = float(os.environ.get('RCH_TIMING_SCALE', '1'))
    if not math.isfinite(timing_scale) or not 1.0 <= timing_scale <= 10.0:
        raise ValueError('scale outside [1, 10]')
except ValueError:
    print('RCH_SOURCE_NAMESPACE_INVALID_TIMING_SCALE', file=sys.stderr)
    sys.exit(78)
started = time.monotonic()
try:
    lock = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError('invalid metadata lock inode')
    while True:
        named = os.stat(sys.argv[1], follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise OSError('metadata lock changed while waiting')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES):
                raise
        elapsed = time.monotonic() - started
        if elapsed >= 5 * timing_scale:
            print('RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY elapsed_ms={} lock={}'.format(
                int(elapsed * 1000), sys.argv[1]), file=sys.stderr)
            sys.exit(76)
        time.sleep(0.02)
    named = os.stat(sys.argv[1], follow_symlinks=False)
    if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        raise OSError('metadata lock changed after acquisition')
    os.set_inheritable(lock, True)
    os.execvp(sys.argv[2], sys.argv[2:])
except OSError as error:
    print('RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID {}'.format(error), file=sys.stderr)
    sys.exit(73)
"#;

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
    let deadline = tokio::time::Instant::now()
        + wait_timeout.min(rch_common::timing::scale_duration(SOURCE_ADMISSION_WAIT));
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
        "{setup}rch_source_attempt() {{ (\nset -eu\n\
         exec python3 -I -S -c {lock_program} \"$registry/metadata.lock\" sh -c {script} \
         rch-source-namespace \"$registry\" {identity} {digest} topology {check} {create} \
         <<'RCH_NAMESPACE_SCOPE'\n{body}RCH_NAMESPACE_SCOPE\n\
         ); }}\nrch_admission_attempts=6\n{ADMISSION}",
        setup = super::ssh::source_registry_setup(registry),
        lock_program = quote(REGISTRY_LOCK),
        script = quote(&registry_script),
        identity = quote(identity),
        check = quote(&paths("check")),
        create = quote(&paths("create")),
    ))
}

/// Batch the read-only destination guards and topology observation with the
/// initializer. They still run before registry setup or any namespace write;
/// the registry transaction independently rechecks the physical mapping under
/// its mutex. Keeping this on one bounded channel saves two SSH round trips
/// without caching an observation or granting any source authority.
fn namespace_preflight_command(
    policy: &PathTopologyPolicy,
    identity: &str,
    registry: &str,
    source_roots: &[PathBuf],
) -> anyhow::Result<String> {
    let initializer = namespace_command(policy, identity, registry)?;
    let mut guard = String::from("set -eu\n");
    for root in source_roots {
        let root = root.to_str().context("source destination is not UTF-8")?;
        guard.push_str(&crate::transfer::live_checkout_sync_guard(root));
        guard.push_str(" || exit 73\n");
    }
    // The controller accepts only the final topology acknowledgment on stdout.
    // This observation is diagnostic, never permission to skip initialization.
    guard.push_str(&format!(
        "({}) >&2\n",
        super::ssh::build_worker_projects_topology_probe_cmd(policy),
    ));
    // Keep the guard's original 30-second allowance separate from the
    // namespace controller's 15-second mutation deadline. This finite RPC has
    // no source grant yet and owns only its read-only guard process group.
    let guard = crate::transfer::source_activity_bounded_script(
        "",
        &guard,
        rch_common::timing::scale_duration(Duration::from_secs(30)),
    );
    let controller = shell_escape::escape(CONTROL.into());
    let mut delimiter = format!("RCH_NAMESPACE_{}", uuid::Uuid::new_v4().simple());
    while initializer.lines().any(|line| line == delimiter) {
        delimiter.push('_');
    }
    // Parse the entire compound before running either operation. A truncated
    // stdin upload cannot launch a partially received initializer.
    Ok(format!(
        "{}{{\n(\n{guard}\n) || exit $?\nsh -c {controller} <<'{delimiter}'\n{initializer}\n{delimiter}\n}}\n",
        rch_common::timing::shell_prefix(),
    ))
}

pub(super) async fn initialize_worker_namespace(
    worker: &WorkerConfig,
    policy: &PathTopologyPolicy,
    identity: &str,
    source_roots: &[PathBuf],
) -> anyhow::Result<bool> {
    let script = namespace_preflight_command(policy, identity, REGISTRY, source_roots)?;
    // Bound the worker as well as the SSH client. Killing only the local SSH
    // process can leave a queued initializer or a pipe-holding descendant on
    // the worker, retaining the registry mutex after this future has failed.
    // Both controllers own only pre-intent setup, never a source/build grant.
    let output = run_offload_ssh_command_with_stdin(
        worker,
        "sh -s",
        script.as_bytes(),
        rch_common::timing::scale_duration(Duration::from_secs(50)),
    )
    .await?;
    if output.status.success() && output.stdout.as_slice() == b"RCH_TOPOLOGY_OK\n" {
        return Ok(output
            .stderr
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"RCH_TOPOLOGY_INITIALIZATION_REQUIRED"));
    }
    Err(namespace_refusal(
        worker,
        policy,
        output.status.code(),
        &output.stderr,
    ))
}

/// The initializer's refusal as an error. Its admission loop already retried
/// a briefly overlapping owner (`rch_admission_attempts`), so an overlap
/// verdict means another owner still holds this worker's source. Typed busy,
/// the release fences the (project, worker) pair (bd-p3kuz). Untyped, rchd
/// kept placing the project on the same worker: vmi1153651 refused it four
/// times in 30 minutes on 2026-10-23 while one long build held the source.
fn namespace_refusal(
    worker: &WorkerConfig,
    policy: &PathTopologyPolicy,
    status: Option<i32>,
    stderr: &[u8],
) -> anyhow::Error {
    let detail = String::from_utf8_lossy(stderr);
    let permanent_mapping = if status == Some(73)
        && !detail.lines().any(|line| {
            [
                "RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED",
                "RCH_SOURCE_NAMESPACE_INTERRUPTED",
                "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED",
                "RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY",
                "RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED",
                "RCH_SOURCE_CANCELLATION_FENCE",
                "RCH: durable source ownership: unfinished overlapping",
            ]
            .iter()
            .any(|marker| line.starts_with(marker))
        }) {
        detail.lines().find(|line| {
            matches!(
                *line,
                "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base"
                    | "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: canonical_not_directory"
            )
        })
    } else {
        None
    };
    let detail = detail.trim();
    let detail = if detail.is_empty() {
        "RCH_SOURCE_NAMESPACE_INTERRUPTED: worker returned no diagnostic; publication and teardown are unconfirmed"
    } else {
        detail
    };
    let topology = rch_common::SourceTopology::from_policy(policy);
    let rendered_detail = permanent_mapping.map_or_else(
        || detail.escape_debug().to_string(),
        |verdict| topology_refusal_detail(verdict, detail, &topology),
    );
    let error = crate::transfer::destination_check_refusal(
        format!(
            "worker source namespace initialization refused on {} (status {:?}): {}",
            worker.id, status, rendered_detail,
        ),
        detail,
    );
    if permanent_mapping.is_some() {
        error.context(SourceTopologyIncompatible {
            worker_id: worker.id.clone(),
            mismatch: rch_common::SourceTopologyMismatch {
                topology,
                detail: rendered_detail,
            },
        })
    } else if status == Some(76) && detail.contains("RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY") {
        error.context(crate::transfer::SourceAuthorityBusy(format!(
            "worker registry metadata lock on {} remained busy; no source grant was admitted",
            worker.id
        )))
    } else if status == Some(75) && retryable_source_admission_error(&error) {
        overlapping_owner_outlived_wait(error, worker)
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::super::SyncClosureMode;
    use super::*;
    use std::path::PathBuf;

    fn test_policy() -> PathTopologyPolicy {
        PathTopologyPolicy::new("/Users/test/projects".into(), "/dp".into())
    }

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
        let source = canonical.join("repository");
        let command = namespace_preflight_command(
            &policy,
            "0123",
            registry.to_str().unwrap(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        for observation in [
            "RCH_TOPOLOGY_INITIALIZATION_REQUIRED",
            "RCH_TOPOLOGY_PATHS_PRESENT",
        ] {
            let mut child = std::process::Command::new("sh")
                .arg("-s")
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
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .any(|line| line == observation)
            );
            assert_eq!(std::fs::canonicalize(&alias).unwrap(), canonical);
            assert!(!source.exists(), "preflight must not create source trees");
            assert!(std::fs::read_dir(&registry).unwrap().all(|entry| {
                let path = entry.unwrap().path();
                !matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("claim" | "pending")
                )
            }));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn namespace_preflight_checks_every_destination_before_any_mutation() {
        use std::io::Write as _;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let canonical = temp.path().join("projects");
        let alias = temp.path().join("alias");
        let registry = temp.path().join("registry");
        let policy = PathTopologyPolicy::new(canonical.clone(), alias.clone());
        // A valid first root must not cause the initializer to run before
        // checking the later unsafe root. Even registry setup is forbidden.
        let command = namespace_preflight_command(
            &policy,
            "0123",
            registry.to_str().unwrap(),
            &[canonical.join("safe repository"), PathBuf::from("/")],
        )
        .unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-s")
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
        assert_eq!(output.status.code(), Some(73));
        assert!(output.stdout.is_empty());
        assert!(!canonical.exists() && !alias.exists() && !registry.exists());
        let worker = WorkerConfig::default();
        let error = namespace_refusal(&worker, &policy, output.status.code(), &output.stderr);
        assert!(
            error.is::<crate::transfer::LiveCheckoutRefused>(),
            "{error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn namespace_preflight_truncated_upload_never_starts_a_program_or_mutates_paths() {
        use std::io::Write as _;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let canonical = temp.path().join("projects with ' quotes");
        let alias = temp.path().join("alias");
        let registry = temp.path().join("registry");
        let policy = PathTopologyPolicy::new(canonical.clone(), alias.clone());
        let source = canonical.join("repository");
        let command = namespace_preflight_command(
            &policy,
            "0123",
            registry.to_str().unwrap(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        assert!(command.ends_with("}\n"));
        let outer_heredoc_end = command.rfind("\nRCH_NAMESPACE_").unwrap();
        // A complete heredoc alone is insufficient: the outer compound must
        // also arrive before even the read-only guards or observation run.
        for (name, end) in [
            ("mid_program", command.len() / 2),
            ("missing_final_heredoc", outer_heredoc_end),
            ("missing_outer_brace", command.len() - 2),
        ] {
            let mut child = std::process::Command::new("sh")
                .arg("-s")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&command.as_bytes()[..end])
                .unwrap();
            let output = child.wait_with_output().unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success(),
                "{name} accepted a truncated command"
            );
            assert!(output.stdout.is_empty(), "{name}");
            assert!(
                !diagnostic.contains("RCH_TOPOLOGY_"),
                "{name}: {diagnostic}"
            );
            assert!(
                !diagnostic.contains("RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED"),
                "{name}: {diagnostic}"
            );
            assert!(!canonical.exists(), "{name}");
            assert!(std::fs::symlink_metadata(&alias).is_err(), "{name}");
            assert!(!registry.exists(), "{name}");
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0, "{name}");
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

    /// An overlap verdict from the initializer must reach the release as
    /// source-busy, or rchd never fences the pair and re-places the project on
    /// the same held worker (2026-10-23). A topology mismatch is a separate type.
    #[test]
    fn namespace_overlap_refusal_is_typed_source_busy() {
        let worker = WorkerConfig {
            id: rch_common::WorkerId::new("w1"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "/tmp/test_key".to_string(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
            tools: Vec::new(),
        };
        for overlap in [
            "RCH: durable source ownership: unfinished overlapping physical source owner\n",
            "RCH: durable source ownership: unfinished overlapping source owner\n",
        ] {
            let error = namespace_refusal(&worker, &test_policy(), Some(75), overlap.as_bytes());
            assert!(crate::transfer::source_authority_busy(&error), "{error:#}");
            assert!(format!("{error:#}").contains("initialization refused on w1"));
            // Only the completed registry overlap status authorizes a busy
            // report. Interrupted/unknown failures can retain older stderr.
            for status in [None, Some(0), Some(73), Some(76), Some(137), Some(255)] {
                let error = namespace_refusal(&worker, &test_policy(), status, overlap.as_bytes());
                assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
            }
        }
        for terminal in [
            "RCH: durable source ownership: invalid claim record\n",
            "RCH_TOPOLOGY_ERR_CANONICAL_NOT_DIRECTORY\n",
        ] {
            let error = namespace_refusal(&worker, &test_policy(), Some(73), terminal.as_bytes());
            assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
        }
    }

    #[test]
    fn source_namespace_permanent_mapping_requires_completed_explicit_verdict() {
        let worker = WorkerConfig {
            id: WorkerId::new("incompatible-worker"),
            ..WorkerConfig::default()
        };
        let policy = test_policy();
        for reason in ["conflicting_alias_base", "canonical_not_directory"] {
            let diagnostic = format!("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: {reason}\n");
            let error = namespace_refusal(&worker, &policy, Some(73), diagnostic.as_bytes())
                .context("outer namespace preflight context");
            let mismatch = error.downcast_ref::<SourceTopologyIncompatible>().unwrap();
            assert_eq!(mismatch.worker_id, worker.id);
            assert_eq!(
                mismatch.mismatch().topology.canonical_root,
                "/Users/test/projects"
            );
            assert_eq!(mismatch.mismatch().topology.alias_root, "/dp");
            assert!(mismatch.mismatch().detail.contains(reason));
            assert!(!crate::transfer::source_authority_busy(&error));
            let message = mismatch.to_string();
            assert!(message.contains("incompatible-worker"));
            assert!(message.contains("choose a worker with a compatible layout"));
            assert!(message.contains("operator correct the configured mapping"));

            // A diagnostic observed before termination, transport failure or
            // contention is not a completed permanent refusal.
            for status in [None, Some(0), Some(75), Some(76), Some(137), Some(255)] {
                let error = namespace_refusal(&worker, &policy, status, diagnostic.as_bytes());
                assert!(error.downcast_ref::<SourceTopologyIncompatible>().is_none());
            }
            for uncertain in [
                "RCH_SOURCE_NAMESPACE_CONTROL_UNSETTLED status=137",
                "RCH_SOURCE_NAMESPACE_INTERRUPTED",
                "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status=137",
                "RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY elapsed_ms=5000",
                "RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED",
                "RCH_SOURCE_CANCELLATION_FENCE",
                "RCH: durable source ownership: unfinished overlapping source owner",
            ] {
                let mixed = format!("{diagnostic}{uncertain}\n");
                let error = namespace_refusal(&worker, &policy, Some(73), mixed.as_bytes());
                assert!(error.downcast_ref::<SourceTopologyIncompatible>().is_none());
                assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
            }
        }
        for diagnostic in [
            "RCH: source namespace: conflicting alias base",
            "prefix RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base",
            " RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base",
            "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base suffix",
            "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: unknown",
            "RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID invalid lock inode",
            "RCH: source namespace: cannot create canonical base",
            "RCH: source namespace: namespace changed during initialization",
            "RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED",
            "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status=137",
        ] {
            let error = namespace_refusal(&worker, &policy, Some(73), diagnostic.as_bytes());
            assert!(error.downcast_ref::<SourceTopologyIncompatible>().is_none());
        }
    }

    #[test]
    fn source_namespace_mapping_diagnostic_is_bounded_and_control_safe() {
        let worker = WorkerConfig::default();
        let paths = serde_json::json!({
            "canonical": "/Users/test/projects",
            "alias": "/dp",
            "canonical_physical": format!("/canonical\u{1b}[31m/{}", "é".repeat(5000)),
            "alias_physical": "/physical\t/alias",
        });
        let diagnostic = format!(
            "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base\n\
             RCH_SOURCE_TOPOLOGY_PATHS {paths}\n"
        );
        let error = namespace_refusal(&worker, &test_policy(), Some(73), diagnostic.as_bytes());
        let mismatch = error.downcast_ref::<SourceTopologyIncompatible>().unwrap();
        assert!(mismatch.mismatch().detail.len() <= 4096);
        assert!(mismatch.mismatch().detail.contains("[truncated]"));
        assert!(mismatch.mismatch().detail.contains("alias_physical="));
        assert!(!mismatch.mismatch().detail.chars().any(char::is_control));
        assert!(!format!("{error:#}").chars().any(char::is_control));
    }

    #[test]
    fn source_namespace_permanent_diagnostics_ignore_unrelated_or_unbound_data() {
        let worker = WorkerConfig::default();
        let mapping = serde_json::json!({
            "canonical": "/Users/test/projects",
            "canonical_physical": "/worker/canonical",
            "alias": "/dp",
            "alias_physical": "/worker/other-projects",
        });
        let verdict = "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base";
        let diagnostic = format!(
            "private startup/source sentinel\n{verdict}\nRCH_SOURCE_TOPOLOGY_PATHS {mapping}\nprivate trailing source sentinel\n"
        );
        let error = namespace_refusal(&worker, &test_policy(), Some(73), diagnostic.as_bytes());
        let mismatch = error.downcast_ref::<SourceTopologyIncompatible>().unwrap();
        assert!(mismatch.mismatch().detail.contains("/worker/canonical"));
        assert!(
            mismatch
                .mismatch()
                .detail
                .contains("/worker/other-projects")
        );
        assert!(!mismatch.to_string().contains("sentinel"));
        assert!(!format!("{error:#}").contains("sentinel"));
        mismatch.mismatch().validate().unwrap();

        for changed in ["canonical", "alias", "unexpected_key", "alias_physical"] {
            let mut mapping = mapping.clone();
            mapping[changed] = serde_json::Value::String("private source sentinel".into());
            let diagnostic = format!("{verdict}\nRCH_SOURCE_TOPOLOGY_PATHS {mapping}\n");
            let error = namespace_refusal(&worker, &test_policy(), Some(73), diagnostic.as_bytes());
            let mismatch = error.downcast_ref::<SourceTopologyIncompatible>().unwrap();
            assert!(mismatch.mismatch().detail.contains("metadata unavailable"));
            assert!(!format!("{error:#}").contains("sentinel"));
        }
        // Conflicting duplicate metadata must not select an arbitrary physical
        // mapping even when both copies name the requested logical roots.
        let mut second = mapping.clone();
        second["alias_physical"] = serde_json::Value::String("/different/physical".into());
        let diagnostic = format!(
            "{verdict}\nRCH_SOURCE_TOPOLOGY_PATHS {mapping}\nRCH_SOURCE_TOPOLOGY_PATHS {second}\n"
        );
        let error = namespace_refusal(&worker, &test_policy(), Some(73), diagnostic.as_bytes());
        let mismatch = error.downcast_ref::<SourceTopologyIncompatible>().unwrap();
        assert!(mismatch.mismatch().detail.contains("metadata unavailable"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_namespace_production_conflict_preserves_roots_and_is_permanent() {
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt as _, symlink};
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let canonical = temp.path().join("Users/test/projects");
        let physical = temp.path().join("data/projects");
        let alias = temp.path().join("dp");
        let registry = temp.path().join("registry");
        std::fs::create_dir_all(&canonical).unwrap();
        std::fs::create_dir_all(&physical).unwrap();
        std::fs::write(canonical.join("keep"), b"canonical source contents").unwrap();
        std::fs::write(physical.join("keep"), b"other source contents").unwrap();
        symlink(&physical, &alias).unwrap();
        let inode = std::fs::symlink_metadata(&alias).unwrap().ino();
        let policy = PathTopologyPolicy::new(canonical.clone(), alias.clone());
        let command = namespace_command(&policy, "0123", registry.to_str().unwrap()).unwrap();
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
        assert_eq!(output.status.code(), Some(73));
        assert!(output.stdout.is_empty());
        let worker = WorkerConfig {
            id: WorkerId::new("different-layout"),
            ..WorkerConfig::default()
        };
        let error = namespace_refusal(&worker, &policy, output.status.code(), &output.stderr);
        assert!(error.is::<SourceTopologyIncompatible>(), "{error:#}");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains(physical.to_str().unwrap()));
        assert!(diagnostic.contains(canonical.to_str().unwrap()));
        assert!(!diagnostic.contains("source contents"));
        assert_eq!(std::fs::symlink_metadata(&alias).unwrap().ino(), inode);
        assert_eq!(std::fs::read_link(&alias).unwrap(), physical);
        assert_eq!(
            std::fs::read(canonical.join("keep")).unwrap(),
            b"canonical source contents"
        );
        assert_eq!(
            std::fs::read(physical.join("keep")).unwrap(),
            b"other source contents"
        );
        assert!(std::fs::read_dir(registry).unwrap().all(|entry| {
            !matches!(
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("claim" | "pending")
            )
        }));
    }

    #[test]
    fn source_namespace_restores_absent_canonical_name_beside_a_real_alias() {
        use std::io::Write as _;
        use std::os::unix::fs::symlink;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let physical = root.join("data/projects");
        let alias = root.join("dp");
        let registry = root.join("registry");
        std::fs::create_dir_all(&physical).unwrap();
        std::fs::write(physical.join("keep"), b"source contents").unwrap();
        symlink(&physical, &alias).unwrap();
        let run = |canonical: &std::path::Path| {
            let policy = PathTopologyPolicy::new(canonical.to_path_buf(), alias.clone());
            let command = namespace_command(&policy, "0123", registry.to_str().unwrap()).unwrap();
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
            child.wait_with_output().unwrap()
        };

        // The parent is absent too, as on a worker whose home was never populated.
        let canonical = root.join("Users/test/projects");
        for _ in 0..2 {
            let output = run(&canonical);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"RCH_TOPOLOGY_OK\n");
            assert_eq!(std::fs::read_link(&canonical).unwrap(), physical);
        }
        assert_eq!(std::fs::read_link(&alias).unwrap(), physical);
        assert_eq!(
            std::fs::read(canonical.join("keep")).unwrap(),
            b"source contents"
        );

        // A link that cannot be made stays the permanent refusal it always was,
        // and leaves no second tree behind.
        let blocked = root.join("blocked");
        std::fs::write(&blocked, b"a file, not a directory").unwrap();
        let output = run(&blocked.join("projects"));
        assert_eq!(output.status.code(), Some(73));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base")
        );
        assert_eq!(std::fs::read(&blocked).unwrap(), b"a file, not a directory");
    }

    #[test]
    fn source_namespace_metadata_busy_requires_status_and_explicit_lock_verdict() {
        let worker = WorkerConfig {
            id: rch_common::WorkerId::new("metadata-worker"),
            host: "localhost".to_owned(),
            user: "test".to_owned(),
            identity_file: "/tmp/test_key".to_owned(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
            tools: vec![],
        };
        let busy = b"RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY elapsed_ms=5003 lock=/registry/metadata.lock\n";
        let error = namespace_refusal(&worker, &test_policy(), Some(76), busy);
        assert!(crate::transfer::source_authority_busy(&error), "{error:#}");
        let detail = format!("{error:#}");
        assert!(detail.contains("metadata-worker"));
        assert!(detail.contains("elapsed_ms=5003"));
        assert!(detail.contains("no source grant was admitted"));

        // A killed/interrupted controller might have captured a busy line
        // before failing elsewhere. That is not a completed busy verdict.
        for status in [None, Some(73), Some(137)] {
            let error = namespace_refusal(&worker, &test_policy(), status, busy);
            assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
            assert!(format!("{error:#}").contains("elapsed_ms=5003"));
        }
        for refusal in [
            "RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID metadata lock changed while waiting",
            "RCH_SOURCE_CANCELLATION_FENCE identity=abc record=/registry/abc.cancelling",
            "RCH_SOURCE_REGISTRY_PUBLICATION_UNCONFIRMED identity=abc operation=topology stage=publish",
            "RCH_SOURCE_NAMESPACE_PROCESS_TERMINATED status=137 signal=9 signal_origin=unknown",
            "Killed",
        ] {
            for status in [Some(73), Some(76)] {
                let error = namespace_refusal(&worker, &test_policy(), status, refusal.as_bytes());
                assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
                assert!(format!("{error:#}").contains(refusal));
            }
        }
    }

    #[test]
    fn source_namespace_empty_diagnostic_reports_uncertain_publication_and_teardown() {
        let worker = WorkerConfig {
            id: rch_common::WorkerId::new("silent-worker"),
            host: "localhost".to_owned(),
            user: "test".to_owned(),
            identity_file: "/tmp/test_key".to_owned(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
            tools: vec![],
        };
        for status in [None, Some(73), Some(76), Some(137)] {
            for stderr in [b"".as_slice(), b" \n\t".as_slice()] {
                let error = namespace_refusal(&worker, &test_policy(), status, stderr);
                assert!(!crate::transfer::source_authority_busy(&error), "{error:#}");
                let detail = format!("{error:#}");
                assert!(detail.contains("silent-worker"));
                assert!(detail.contains("RCH_SOURCE_NAMESPACE_INTERRUPTED"));
                assert!(detail.contains("publication and teardown are unconfirmed"));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_namespace_registry_lock_process_protocol() {
        let fixture = tempfile::tempdir().unwrap().keep();
        let compiled = fixture.join("registry-lock.py");
        std::fs::write(&compiled, REGISTRY_LOCK).unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../scripts/tests/test_source_namespace_control.py");
        let output = std::process::Command::new("python3")
            .arg(script)
            .arg("SourceNamespaceRegistryLockTests")
            .env("RCH_TEST_SOURCE_NAMESPACE_REGISTRY_LOCK", &compiled)
            .output()
            .expect("Python 3 is required for native registry-lock qualification");
        assert!(
            output.status.success(),
            "metadata-lock qualification failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
