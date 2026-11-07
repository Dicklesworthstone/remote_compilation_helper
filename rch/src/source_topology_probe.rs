//! Read-only checks of the namespace requested by this dispatcher.
//!
//! A worker's default capability roots can be healthy while this dispatcher's
//! canonical root is missing or conflicts with its alias. Send the admission
//! path program in check mode so diagnostics use the same physical-path rule,
//! independently of the deployed worker binary. These observations never
//! repair paths, acquire source ownership, or change placement fences.

use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use rch_common::{RchConfig, SourceTopology, WorkerConfig};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(any(unix, test))]
const PATHS: &str = include_str!("hook/source_namespace_paths.sh");
#[cfg(any(unix, test))]
const REPORT_PREFIX: &str = "RCH_SOURCE_TOPOLOGY_CHECK_V1 ";
#[cfg(any(unix, test))]
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_PROBES: usize = 8;
#[cfg(unix)]
const WORKER_TIMEOUT: Duration = Duration::from_secs(8);
// Leave room inside the reliability doctor's ten-second probe deadline.
const FLEET_TIMEOUT: Duration = Duration::from_secs(9);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTopologyOutcome {
    Compatible,
    CanonicalMissing,
    AliasMissing,
    CanonicalNotDirectory,
    AliasNotDirectory,
    ConflictingAliasBase,
    Unavailable,
    Skipped,
}

impl SourceTopologyOutcome {
    pub fn is_defect(self) -> bool {
        !matches!(self, Self::Compatible | Self::Unavailable | Self::Skipped)
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::Compatible => "configured dispatcher source namespace matches",
            Self::CanonicalMissing => "dispatcher canonical root is missing on the worker",
            Self::AliasMissing => "dispatcher alias root is missing on the worker",
            Self::CanonicalNotDirectory => "dispatcher canonical root is not a directory",
            Self::AliasNotDirectory => "dispatcher alias root is not a directory",
            Self::ConflictingAliasBase => {
                "dispatcher canonical and alias roots resolve differently"
            }
            Self::Unavailable => "dispatcher source namespace could not be checked",
            Self::Skipped => "dispatcher source namespace check does not apply",
        }
    }

    #[cfg(any(unix, test))]
    fn exit_code(self) -> Option<i32> {
        match self {
            Self::Compatible => Some(0),
            Self::Unavailable => Some(2),
            Self::Skipped => None,
            _ => Some(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceTopologyProbe {
    /// Effective namespace for ordinary builds with this dispatcher config.
    /// Off-root scratch layouts use the worker staging base. Invocation-specific
    /// overlays are checked separately at dispatch. Absent on config failure.
    pub topology: Option<SourceTopology>,
    pub outcome: SourceTopologyOutcome,
    pub canonical_physical: Option<String>,
    pub alias_physical: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SourceTopologyProbe {
    pub fn unavailable(topology: Option<&SourceTopology>, detail: &str) -> Self {
        Self {
            topology: topology.cloned(),
            outcome: SourceTopologyOutcome::Unavailable,
            canonical_physical: None,
            alias_physical: None,
            detail: Some(bounded_detail(detail)),
        }
    }

    /// Path data can contain terminal controls through a worker-side symlink.
    /// Debug quoting preserves that evidence without printing raw controls.
    pub fn describe(&self) -> String {
        let mut description = self.outcome.summary().to_string();
        if let Some(topology) = &self.topology {
            description.push_str(&format!(
                "; canonical={:?}; alias={:?}; canonical_physical={:?}; alias_physical={:?}",
                topology.canonical_root,
                topology.alias_root,
                self.canonical_physical.as_deref().unwrap_or("<unresolved>"),
                self.alias_physical.as_deref().unwrap_or("<unresolved>"),
            ));
        }
        if let Some(detail) = &self.detail {
            description.push_str("; ");
            description.push_str(detail);
        }
        description
    }
}

fn bounded_detail(detail: &str) -> String {
    let mut bounded = String::new();
    for character in detail.escape_debug() {
        if bounded.len() + character.len_utf8() > 2048 {
            bounded.push_str(" [truncated]");
            break;
        }
        bounded.push(character);
    }
    bounded
}

pub fn requested_topology(config: &RchConfig) -> Result<SourceTopology, String> {
    SourceTopology::for_worker_namespace(
        &config.path_topology.to_policy(),
        false,
        &config.transfer.remote_base,
    )
    .map_err(|error| format!("invalid dispatcher source topology: {error}"))
}

pub fn load_requested_topology() -> Result<SourceTopology, String> {
    let config = crate::config::load_config()
        .map_err(|error| format!("cannot load dispatcher topology configuration: {error}"))?;
    requested_topology(&config)
}

#[cfg(any(unix, test))]
fn build_check_command(topology: &SourceTopology) -> Result<String, String> {
    topology.validate().map_err(str::to_owned)?;
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    Ok(format!(
        "sh -c {} rch-source-topology check {} {} --report-json",
        quote(PATHS),
        quote(&topology.canonical_root),
        quote(&topology.alias_root),
    ))
}

#[cfg(any(unix, test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReport {
    canonical: String,
    alias: String,
    canonical_physical: Option<String>,
    alias_physical: Option<String>,
    outcome: SourceTopologyOutcome,
}

#[cfg(any(unix, test))]
fn parse_output(
    topology: &SourceTopology,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> SourceTopologyProbe {
    let invalid = |reason| SourceTopologyProbe::unavailable(Some(topology), reason);
    if topology.validate().is_err() {
        return invalid("requested topology is invalid");
    }
    if stdout.len() > MAX_REPORT_BYTES || !stderr.trim().is_empty() {
        return invalid("namespace check returned oversized output or unexpected stderr");
    }
    let Some(line) = stdout
        .strip_suffix('\n')
        .filter(|line| !line.contains(['\n', '\r']))
    else {
        return invalid("namespace check did not return one complete report");
    };
    let Some(body) = line.strip_prefix(REPORT_PREFIX) else {
        return invalid("namespace check report marker is missing");
    };
    let Ok(report) = serde_json::from_str::<WireReport>(body) else {
        return invalid("namespace check report is malformed or has unknown fields");
    };
    if report.canonical != topology.canonical_root || report.alias != topology.alias_root {
        return invalid("namespace check reported roots other than the requested dispatcher roots");
    }
    let valid_physical = |path: &Option<String>| {
        path.as_ref().is_none_or(|path| {
            path.starts_with('/') && path.len() <= 4096 && !path.contains(['\0', '\n', '\r'])
        })
    };
    if !valid_physical(&report.canonical_physical) || !valid_physical(&report.alias_physical) {
        return invalid("namespace check reported invalid physical-path metadata");
    }
    if report.outcome.exit_code() != Some(exit_code) {
        return invalid("namespace check exit status did not agree with its report");
    }
    if matches!(
        report.outcome,
        SourceTopologyOutcome::Compatible | SourceTopologyOutcome::ConflictingAliasBase
    ) {
        let (Some(canonical), Some(alias)) = (&report.canonical_physical, &report.alias_physical)
        else {
            return invalid("namespace verdict omitted a physical root");
        };
        if (canonical == alias) != (report.outcome == SourceTopologyOutcome::Compatible) {
            return invalid("namespace verdict contradicted its physical roots");
        }
    }
    SourceTopologyProbe {
        topology: Some(topology.clone()),
        outcome: report.outcome,
        canonical_physical: report.canonical_physical,
        alias_physical: report.alias_physical,
        detail: (report.outcome == SourceTopologyOutcome::Unavailable)
            .then(|| "worker could not complete the namespace check".to_string()),
    }
}

fn skipped_probe(
    worker: &WorkerConfig,
    requested: &Result<SourceTopology, String>,
) -> Option<SourceTopologyProbe> {
    let reason = if rch_common::declared_os(&worker.tags).as_deref() == Some("windows") {
        "Windows workers do not use the Unix canonical/alias namespace"
    } else if rch_common::mock::is_mock_enabled() || rch_common::mock::is_mock_worker(worker) {
        "mock transport does not establish a worker's physical namespace"
    } else if !cfg!(unix) {
        "remote namespace probing requires a Unix dispatcher"
    } else {
        return None;
    };
    let mut result = SourceTopologyProbe::unavailable(requested.as_ref().ok(), reason);
    result.outcome = SourceTopologyOutcome::Skipped;
    Some(result)
}

#[cfg(unix)]
pub async fn probe_connected(
    client: &rch_common::SshClient,
    worker: &WorkerConfig,
    requested: &Result<SourceTopology, String>,
) -> SourceTopologyProbe {
    if let Some(skipped) = skipped_probe(worker, requested) {
        return skipped;
    }
    let topology = match requested {
        Ok(topology) => topology,
        Err(error) => return SourceTopologyProbe::unavailable(None, error),
    };
    let command = match build_check_command(topology) {
        Ok(command) => command,
        Err(error) => return SourceTopologyProbe::unavailable(Some(topology), &error),
    };
    match client.execute_with_timeout(&command, WORKER_TIMEOUT).await {
        Ok(output) => parse_output(topology, output.exit_code, &output.stdout, &output.stderr),
        Err(error) => SourceTopologyProbe::unavailable(
            Some(topology),
            &format!("namespace SSH check failed: {error}"),
        ),
    }
}

async fn probe_worker(
    worker: &WorkerConfig,
    requested: &Result<SourceTopology, String>,
) -> SourceTopologyProbe {
    if let Some(skipped) = skipped_probe(worker, requested) {
        return skipped;
    }
    let topology = match requested {
        Ok(topology) => topology,
        Err(error) => return SourceTopologyProbe::unavailable(None, error),
    };
    #[cfg(unix)]
    {
        let options = rch_common::SshOptions {
            connect_timeout: Duration::from_secs(5),
            command_timeout: WORKER_TIMEOUT,
            ..Default::default()
        };
        let mut client = rch_common::SshClient::new(worker.clone(), options);
        let operation = async {
            if let Err(error) = client.connect().await {
                return SourceTopologyProbe::unavailable(
                    Some(topology),
                    &format!("namespace SSH connection failed: {error}"),
                );
            }
            let result = probe_connected(&client, worker, requested).await;
            let _ = client.disconnect().await;
            result
        };
        match tokio::time::timeout(WORKER_TIMEOUT, operation).await {
            Ok(result) => result,
            Err(_) => SourceTopologyProbe::unavailable(
                Some(topology),
                "namespace SSH check exceeded its eight-second deadline",
            ),
        }
    }
    #[cfg(not(unix))]
    SourceTopologyProbe::unavailable(Some(topology), "Unix SSH transport is unavailable")
}

/// At most eight SSH probes run at once; a nine-second fleet deadline also
/// bounds large or entirely unreachable fleets. Unfinished workers retain an
/// explicit unavailable result in configuration order. Dropping pending
/// futures retires their owned SSH clients, rather than leaving detached tasks.
pub fn probe_fleet<'a>(
    workers: &'a [WorkerConfig],
    requested: &'a Result<SourceTopology, String>,
) -> BoxFuture<'a, Vec<SourceTopologyProbe>> {
    let fallback = SourceTopologyProbe::unavailable(
        requested.as_ref().ok(),
        "namespace check did not complete within the fleet deadline",
    );
    // Erase the borrowed async-function iterator before it crosses the
    // doctor's spawned-task boundary (Rust issue #100013). Each future still
    // owns its SSH client and is polled only under the same concurrency cap.
    let probes: Vec<BoxFuture<'_, SourceTopologyProbe>> = workers
        .iter()
        .map(|worker| probe_worker(worker, requested).boxed())
        .collect();
    collect_bounded(probes, vec![fallback; workers.len()], FLEET_TIMEOUT)
}

fn collect_bounded<'a>(
    probes: Vec<BoxFuture<'a, SourceTopologyProbe>>,
    mut results: Vec<SourceTopologyProbe>,
    budget: Duration,
) -> BoxFuture<'a, Vec<SourceTopologyProbe>> {
    async move {
        let mut queued = probes.into_iter().enumerate();
        let mut pending = FuturesUnordered::new();
        for _ in 0..MAX_CONCURRENT_PROBES {
            if let Some((index, probe)) = queued.next() {
                pending.push(indexed_probe(index, probe));
            }
        }
        let _ = tokio::time::timeout(budget, async {
            while let Some((index, result)) = pending.next().await {
                results[index] = result;
                if let Some((next_index, probe)) = queued.next() {
                    pending.push(indexed_probe(next_index, probe));
                }
            }
        })
        .await;
        results
    }
    .boxed()
}

fn indexed_probe<'a>(
    index: usize,
    probe: BoxFuture<'a, SourceTopologyProbe>,
) -> BoxFuture<'a, (usize, SourceTopologyProbe)> {
    async move { (index, probe.await) }.boxed()
}

#[cfg(all(test, unix))]
pub(crate) fn probe_local_for_test(
    topology: &SourceTopology,
    working_directory: &std::path::Path,
) -> SourceTopologyProbe {
    let output = std::process::Command::new("sh")
        .args([
            "-c",
            &build_check_command(topology).expect("valid fixture topology"),
        ])
        .current_dir(working_directory)
        .output()
        .expect("execute the production namespace check command");
    parse_output(
        topology,
        output.status.code().unwrap_or(-1),
        std::str::from_utf8(&output.stdout).expect("ASCII JSON report"),
        std::str::from_utf8(&output.stderr).expect("UTF-8 shell diagnostic"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn topology() -> SourceTopology {
        SourceTopology {
            canonical_root: "/Users/dispatcher/projects".to_string(),
            alias_root: "/dp".to_string(),
        }
    }

    fn report() -> serde_json::Value {
        serde_json::json!({
            "canonical": "/Users/dispatcher/projects",
            "alias": "/dp",
            "canonical_physical": "/data/projects",
            "alias_physical": "/data/projects",
            "outcome": "compatible",
        })
    }

    fn encode(report: &serde_json::Value) -> String {
        format!("{REPORT_PREFIX}{report}\n")
    }

    #[test]
    fn requested_topology_uses_dispatcher_roots_and_offroot_staging_policy() {
        let mut config = RchConfig::default();
        config.path_topology.canonical_root = Some("/Users/dispatcher/projects".to_string());
        config.path_topology.alias_root = Some("/dp".to_string());
        config.transfer.remote_base = "/data/tmp/rch".to_string();
        assert_eq!(requested_topology(&config).unwrap(), topology());

        for (canonical, alias, explicit_override) in [
            ("/scratch/checkout", "/scratch/checkout/.rch-alias", false),
            ("/private/tmp/checkout", "/dp", false),
            ("/var/folders/a/checkout", "/dp", false),
            ("/scratch/checkout", "/dp", true),
        ] {
            config.path_topology.canonical_root = Some(canonical.to_string());
            config.path_topology.alias_root = Some(alias.to_string());
            config.path_topology.off_root = explicit_override;
            assert_eq!(
                requested_topology(&config).unwrap(),
                SourceTopology {
                    canonical_root: "/data/tmp/rch".to_string(),
                    alias_root: "/data/tmp/rch".to_string(),
                },
                "off-root {canonical} must not require a worker-global alias",
            );
        }
        config.transfer.remote_base = "relative/staging".to_string();
        assert!(requested_topology(&config).is_err());
    }

    #[test]
    fn malformed_or_unscoped_reports_cannot_prove_readiness() {
        let valid = encode(&report());
        let mut wrong_roots = report();
        wrong_roots["canonical"] = "/data/projects".into();
        let mut wrong_physical = report();
        wrong_physical["alias_physical"] = "/other/projects".into();
        let mut omitted_physical = report();
        omitted_physical["canonical_physical"] = serde_json::Value::Null;
        let mut relative_physical = report();
        relative_physical["alias_physical"] = "relative".into();
        let mut unknown_field = report();
        unknown_field["repair"] = true.into();
        let mut unknown_outcome = report();
        unknown_outcome["outcome"] = "maybe".into();
        let mut skipped = report();
        skipped["outcome"] = "skipped".into();
        let duplicate_field = format!(
            "{REPORT_PREFIX}{{\"canonical\":\"/Users/dispatcher/projects\",{}\n",
            &report().to_string()[1..],
        );
        for (stdout, exit_code, stderr) in [
            (String::new(), 0, ""),
            (valid.trim_end().to_string(), 0, ""),
            (format!("{valid}{valid}"), 0, ""),
            (format!("startup banner\n{valid}"), 0, ""),
            (valid.clone(), 1, ""),
            (valid.clone(), -1, ""),
            (valid.clone(), 0, "unexpected diagnostic"),
            (encode(&wrong_roots), 0, ""),
            (encode(&wrong_physical), 0, ""),
            (encode(&omitted_physical), 0, ""),
            (encode(&relative_physical), 0, ""),
            (encode(&unknown_field), 0, ""),
            (encode(&unknown_outcome), 0, ""),
            (encode(&skipped), 0, ""),
            (duplicate_field, 0, ""),
            ("x".repeat(MAX_REPORT_BYTES + 1), 0, ""),
        ] {
            let parsed = parse_output(&topology(), exit_code, &stdout, stderr);
            assert_eq!(
                parsed.outcome,
                SourceTopologyOutcome::Unavailable,
                "{parsed:?}"
            );
            assert_eq!(parsed.topology.as_ref(), Some(&topology()));
        }
        assert_eq!(
            parse_output(&topology(), 0, &valid, "").outcome,
            SourceTopologyOutcome::Compatible,
        );
    }

    #[test]
    fn a_conflict_requires_different_complete_physical_paths_and_exit_one() {
        let mut conflict = report();
        conflict["outcome"] = "conflicting_alias_base".into();
        assert_eq!(
            parse_output(&topology(), 1, &encode(&conflict), "").outcome,
            SourceTopologyOutcome::Unavailable,
        );
        conflict["canonical_physical"] = "/Users/dispatcher/projects".into();
        let parsed = parse_output(&topology(), 1, &encode(&conflict), "");
        assert_eq!(parsed.outcome, SourceTopologyOutcome::ConflictingAliasBase);
        assert!(parsed.describe().contains("/Users/dispatcher/projects"));
        assert!(parsed.describe().contains("/data/projects"));
        assert_eq!(
            parse_output(&topology(), 0, &encode(&conflict), "").outcome,
            SourceTopologyOutcome::Unavailable,
        );
    }

    #[test]
    fn command_rejects_invalid_requested_roots_before_ssh() {
        for root in ["relative", "/projects/../other", "/projects\nunsafe", "/"] {
            let mut invalid = topology();
            invalid.canonical_root = root.to_string();
            assert!(build_check_command(&invalid).is_err(), "{root:?}");
        }
    }

    #[test]
    fn physical_paths_and_transport_details_are_safe_for_terminal_output() {
        let mut conflict = report();
        conflict["outcome"] = "conflicting_alias_base".into();
        conflict["alias_physical"] = "/other/\u{1b}[31m\tprojects".into();
        let parsed = parse_output(&topology(), 1, &encode(&conflict), "");
        assert_eq!(parsed.outcome, SourceTopologyOutcome::ConflictingAliasBase);
        assert!(!parsed.describe().contains(['\u{1b}', '\t']));
        let unavailable = SourceTopologyProbe::unavailable(None, &"\u{1b}\n".repeat(5000));
        assert!(unavailable.detail.as_ref().unwrap().len() < 2100);
        assert!(!unavailable.describe().contains(['\u{1b}', '\n']));
    }

    #[test]
    fn windows_and_mock_workers_are_explicitly_skipped_without_positive_evidence() {
        let windows = WorkerConfig {
            tags: vec!["os:windows".to_string()],
            ..Default::default()
        };
        let mocked = WorkerConfig {
            host: "mock://fixture".to_string(),
            ..Default::default()
        };
        for worker in [windows, mocked] {
            let skipped = skipped_probe(&worker, &Ok(topology())).unwrap();
            assert_eq!(skipped.outcome, SourceTopologyOutcome::Skipped);
            assert!(skipped.canonical_physical.is_none());
            assert!(skipped.alias_physical.is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn actual_check_command_quotes_roots_and_preserves_matching_symlinks() {
        use std::os::unix::fs::{MetadataExt as _, symlink};
        let fixture = tempfile::tempdir().unwrap();
        let canonical = fixture.path().join("projects ' $(touch BAD); spaces");
        let alias = fixture.path().join("alias ' ; touch BAD");
        std::fs::create_dir(&canonical).unwrap();
        symlink(&canonical, &alias).unwrap();
        let inode = std::fs::symlink_metadata(&alias).unwrap().ino();
        let topology = SourceTopology {
            canonical_root: canonical.to_str().unwrap().to_string(),
            alias_root: alias.to_str().unwrap().to_string(),
        };
        let parsed = probe_local_for_test(&topology, fixture.path());
        assert_eq!(
            parsed.outcome,
            SourceTopologyOutcome::Compatible,
            "{parsed:?}"
        );
        assert_eq!(parsed.canonical_physical, parsed.alias_physical);
        assert_eq!(std::fs::symlink_metadata(&alias).unwrap().ino(), inode);
        assert!(!fixture.path().join("BAD").exists());
    }

    #[cfg(unix)]
    #[test]
    fn actual_check_does_not_initialize_missing_dispatcher_roots() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let physical = fixture.path().join("worker-projects");
        let canonical = fixture.path().join("dispatcher/projects");
        let alias = fixture.path().join("alias");
        std::fs::create_dir(&physical).unwrap();
        symlink(&physical, &alias).unwrap();
        let topology = SourceTopology {
            canonical_root: canonical.to_str().unwrap().to_string(),
            alias_root: alias.to_str().unwrap().to_string(),
        };
        let parsed = probe_local_for_test(&topology, fixture.path());
        assert_eq!(
            parsed.outcome,
            SourceTopologyOutcome::CanonicalMissing,
            "{parsed:?}"
        );
        assert!(!canonical.parent().unwrap().exists());
        assert_eq!(std::fs::read_link(&alias).unwrap(), physical);
    }

    struct ActiveProbe(Arc<AtomicUsize>);

    impl Drop for ActiveProbe {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn fleet_collection_caps_concurrency_and_retains_configuration_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let count = MAX_CONCURRENT_PROBES * 2;
        let probes = (0..count)
            .map(|index| {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                async move {
                    let running = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(running, Ordering::SeqCst);
                    let _guard = ActiveProbe(active);
                    tokio::time::sleep(Duration::from_millis((count - index) as u64)).await;
                    SourceTopologyProbe::unavailable(None, &format!("worker-{index}"))
                }
                .boxed()
            })
            .collect();
        let fallback = SourceTopologyProbe::unavailable(None, "deadline");
        let results = collect_bounded(probes, vec![fallback; count], Duration::from_secs(2)).await;
        for (index, result) in results.iter().enumerate() {
            assert_eq!(
                result.detail.as_deref(),
                Some(format!("worker-{index}").as_str())
            );
        }
        assert_eq!(peak.load(Ordering::SeqCst), MAX_CONCURRENT_PROBES);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fleet_deadline_preserves_completed_results_and_cancels_pending_probes() {
        let active = Arc::new(AtomicUsize::new(0));
        let count = MAX_CONCURRENT_PROBES * 2;
        let probes = (0..count)
            .map(|index| {
                let active = Arc::clone(&active);
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = ActiveProbe(active);
                    if index == 3 {
                        parse_output(&topology(), 0, &encode(&report()), "")
                    } else {
                        std::future::pending().await
                    }
                }
                .boxed()
            })
            .collect();
        let fallback = SourceTopologyProbe::unavailable(None, "deadline");
        let results = tokio::time::timeout(
            Duration::from_secs(2),
            collect_bounded(probes, vec![fallback; count], Duration::from_millis(25)),
        )
        .await
        .expect("fleet deadline must bound stalled workers");
        assert_eq!(results[3].outcome, SourceTopologyOutcome::Compatible);
        assert_eq!(
            results
                .iter()
                .filter(|result| result.outcome == SourceTopologyOutcome::Unavailable)
                .count(),
            count - 1,
        );
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "no detached probe futures"
        );
    }
}
