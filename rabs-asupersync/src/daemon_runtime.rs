//! The daemon runtime island (bead S1 / bridge plan Phase S; MILESTONE
//! M2 keystone). FIRST real use of the asupersync runtime in this
//! workspace: everything before this module modeled regions and
//! obligations; this module BOOTS them.
//!
//! The bridge plan's integration contract, held here:
//!
//! - **Regions own lifetimes.** Every subsystem is a region-owned task
//!   spawned through `Cx::spawn`; there are no detached tasks. Dropping
//!   the root cancels the tree (R90's no-orphans claim starts here).
//! - **Cx is the only capability channel.** Subsystem bodies receive
//!   their `Cx` from the runtime; nothing reaches for ambient state.
//! - **Obligations are typed completions.** Each subsystem holds an
//!   [`ObligationSet`] (the D/G-epic model); the shutdown receipt is
//!   generated FROM that accounting — a subsystem that exits with an
//!   open obligation is reported abandoned-with-reason, never silently
//!   dropped. The model layer (`region_tree`) is asserted against the
//!   live spawn ledger at boot: spec and implementation cannot drift
//!   without a test failing.
//! - **Crash evidence survives.** A boot marker (minimal
//!   integrity/recovery control: it prevents the named evidence-loss
//!   mode "kill -9 erases what was running") is written at boot and
//!   removed on clean shutdown; a marker found at boot means the prior
//!   incarnation died unclean, and the recovery report names it.

use crate::obligations::{ObligationKind, ObligationSet};
use crate::region_tree::RegionSpec;
use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::signal::ShutdownController;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The daemon's subsystem regions, in spawn order (plan §12).
pub const DAEMON_SUBSYSTEMS: [&str; 4] = ["edge", "coord", "telemetry", "janitor"];

/// The MODEL of the daemon region tree (spec side of the boot-time
/// spec-vs-implementation assertion).
#[must_use]
pub fn daemon_region_spec() -> RegionSpec {
    RegionSpec {
        name: "rabsd",
        introduces: crate::region_tree::Attribution::default(),
        children: DAEMON_SUBSYSTEMS
            .iter()
            .map(|name| RegionSpec {
                name,
                introduces: crate::region_tree::Attribution::default(),
                children: vec![],
            })
            .collect(),
    }
}

/// One subsystem's shutdown outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemOutcome {
    /// Region name.
    pub name: String,
    /// Obligations all resolved before exit.
    pub obligations_clean: bool,
    /// Reasons for any abandoned obligations (empty when clean).
    pub abandoned: Vec<String>,
}

/// The shutdown receipt, generated from runtime accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReceipt {
    /// Per-subsystem outcomes in spawn order.
    pub subsystems: Vec<SubsystemOutcome>,
    /// Boot-to-ready duration.
    pub boot_ms: u128,
    /// Shutdown-initiated-to-exit duration.
    pub shutdown_ms: u128,
    /// Whether a prior incarnation died unclean (boot marker found).
    pub recovered_from_unclean: bool,
}

impl ShutdownReceipt {
    /// Every subsystem exited with its obligations resolved.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.subsystems.iter().all(|s| s.obligations_clean)
    }

    /// One JSON line for logs/stdout (hand-rolled; daemon logging must
    /// not depend on serde availability in this crate).
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let subsystems: Vec<String> = self
            .subsystems
            .iter()
            .map(|s| {
                format!(
                    "{{\"name\":\"{}\",\"obligations_clean\":{},\"abandoned\":[{}]}}",
                    s.name,
                    s.obligations_clean,
                    s.abandoned
                        .iter()
                        .map(|r| format!("\"{}\"", r.replace('"', "'")))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        format!(
            "{{\"v\":1,\"kind\":\"rabsd-shutdown-receipt\",\"clean\":{},\"boot_ms\":{},\"shutdown_ms\":{},\"recovered_from_unclean\":{},\"subsystems\":[{}]}}",
            self.clean(),
            self.boot_ms,
            self.shutdown_ms,
            self.recovered_from_unclean,
            subsystems.join(",")
        )
    }
}

/// Typed boot/run failure.
#[derive(Debug)]
pub enum DaemonError {
    /// The runtime failed to build.
    RuntimeBuild(String),
    /// A subsystem failed to spawn (admission/region refusal).
    SubsystemSpawn {
        /// Which subsystem.
        name: &'static str,
        /// The spawn error, stringified.
        error: String,
    },
    /// The live spawn ledger diverged from the region-tree model.
    ModelDivergence {
        /// The model's children.
        expected: Vec<String>,
        /// What was actually spawned.
        actual: Vec<String>,
    },
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RuntimeBuild(e) => write!(f, "runtime build failed: {e}"),
            Self::SubsystemSpawn { name, error } => {
                write!(f, "subsystem {name} failed to spawn: {error}")
            }
            Self::ModelDivergence { expected, actual } => write!(
                f,
                "region model divergence: expected {expected:?}, spawned {actual:?}"
            ),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Per-subsystem behavior for lab runs (the abandoned-obligation path
/// must be TESTABLE, so the skeleton takes behavior as data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemBehavior {
    /// Open the lifetime obligation, await shutdown, resolve it.
    Clean,
    /// Hold the obligation open past shutdown (lab-only: exercises the
    /// abandoned-with-reason reporting).
    HoldObligationOpen,
}

/// Real work mounted into a subsystem region: receives the region's Cx
/// and a shutdown receiver, MUST return when shutdown fires, and its
/// Err string becomes an abandoned-obligation reason in the receipt.
pub type SubsystemWork = Box<
    dyn FnOnce(
            Cx,
            asupersync::signal::ShutdownReceiver,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>
        + Send,
>;

/// Options for one daemon run.
pub struct DaemonRunOptions {
    /// Auto-trigger shutdown after this duration (None = wait for
    /// SIGTERM/SIGINT via the asupersync signal listener).
    pub run_for: Option<Duration>,
    /// Boot marker path (crash-evidence control). None disables.
    pub boot_marker: Option<std::path::PathBuf>,
    /// Per-subsystem behavior override (lab); defaults to Clean.
    pub behavior: [SubsystemBehavior; 4],
    /// Real work for the `edge` region (S3+: the UDS server). None =
    /// idle skeleton.
    pub edge_work: Option<SubsystemWork>,
}

impl std::fmt::Debug for DaemonRunOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonRunOptions")
            .field("run_for", &self.run_for)
            .field("boot_marker", &self.boot_marker)
            .field("behavior", &self.behavior)
            .field("edge_work", &self.edge_work.is_some())
            .finish()
    }
}

impl Default for DaemonRunOptions {
    fn default() -> Self {
        Self {
            run_for: None,
            boot_marker: None,
            behavior: [SubsystemBehavior::Clean; 4],
            edge_work: None,
        }
    }
}

/// The obligation each subsystem region holds for its lifetime.
fn lifetime_obligation(name: &str) -> ObligationKind {
    match name {
        "telemetry" => ObligationKind::DiagnosticStream,
        _ => ObligationKind::ProcessGroupDrain,
    }
}

async fn subsystem_body(
    name: &'static str,
    cx: Cx,
    mut shutdown: asupersync::signal::ShutdownReceiver,
    behavior: SubsystemBehavior,
    work: Option<SubsystemWork>,
) -> SubsystemOutcome {
    cx.trace(&format!("rabsd subsystem {name} ready"));
    let mut obligations = ObligationSet::default();
    obligations.open(lifetime_obligation(name));

    // Real work owns the shutdown wait; idle subsystems wait directly.
    let work_result = match work {
        Some(work) => work(cx.clone(), shutdown).await,
        None => {
            shutdown.wait().await;
            Ok(())
        }
    };

    let _ = cx.checkpoint();
    let (obligations_clean, abandoned) = match (behavior, work_result) {
        (SubsystemBehavior::Clean, Ok(())) => {
            match obligations.resolve(lifetime_obligation(name)) {
                Ok(()) => (true, vec![]),
                Err(e) => (false, vec![format!("resolve failed: {e:?}")]),
            }
        }
        (SubsystemBehavior::Clean, Err(reason)) => (false, vec![format!("work failed: {reason}")]),
        (SubsystemBehavior::HoldObligationOpen, _) => (
            false,
            vec![format!(
                "abandoned {:?}: subsystem held it open past shutdown (lab)",
                lifetime_obligation(name)
            )],
        ),
    };
    SubsystemOutcome {
        name: name.to_string(),
        obligations_clean,
        abandoned,
    }
}

/// Boot the runtime island, run the subsystem regions, shut down
/// cleanly, and return the receipt generated from the accounting.
pub fn run_daemon(options: DaemonRunOptions) -> Result<ShutdownReceipt, DaemonError> {
    let boot_start = Instant::now();

    // Crash-evidence marker: found-at-boot means the prior incarnation
    // died unclean (kill -9 / panic-abort).
    let recovered_from_unclean = match &options.boot_marker {
        Some(marker) => {
            let existed = marker.exists();
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(marker, format!("pid={}\n", std::process::id()));
            existed
        }
        None => false,
    };

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|e| DaemonError::RuntimeBuild(format!("{e:?}")))?;

    let controller = Arc::new(ShutdownController::new());
    if options.run_for.is_none() {
        controller.listen_for_signals();
    }
    if let Some(run_for) = options.run_for {
        let timed = Arc::clone(&controller);
        std::thread::spawn(move || {
            std::thread::sleep(run_for);
            timed.shutdown();
        });
    }

    let behavior = options.behavior;
    let mut edge_work = options.edge_work;
    let root_controller = Arc::clone(&controller);
    let handle = runtime.handle();
    let result: Result<ShutdownReceipt, DaemonError> = runtime.block_on(async move {
        handle
            .spawn(async move {
                let cx = Cx::current().expect("runtime task carries a Cx");
                cx.trace("rabsd root region up");

                // Spawn the subsystem regions and keep the live ledger.
                let mut handles = Vec::new();
                let mut spawned: Vec<String> = Vec::new();
                for (index, name) in DAEMON_SUBSYSTEMS.iter().enumerate() {
                    let shutdown = root_controller.subscribe();
                    let subsystem_behavior = behavior[index];
                    let work = if *name == "edge" {
                        edge_work.take()
                    } else {
                        None
                    };
                    let handle = cx
                        .spawn(move |cx| {
                            subsystem_body(name, cx, shutdown, subsystem_behavior, work)
                        })
                        .map_err(|e| DaemonError::SubsystemSpawn {
                            name,
                            error: format!("{e:?}"),
                        })?;
                    spawned.push((*name).to_string());
                    handles.push(handle);
                }

                // Spec-vs-implementation assertion: the live ledger must
                // match the region-tree model (bridge plan contract).
                let expected: Vec<String> = daemon_region_spec()
                    .children
                    .iter()
                    .map(|c| c.name.to_string())
                    .collect();
                if expected != spawned {
                    return Err(DaemonError::ModelDivergence {
                        expected,
                        actual: spawned,
                    });
                }

                let boot_ms = boot_start.elapsed().as_millis();
                cx.trace("rabsd ready");

                // Wait for shutdown, then harvest every subsystem.
                let mut shutdown_rx = root_controller.subscribe();
                shutdown_rx.wait().await;
                let shutdown_start = Instant::now();

                let mut subsystems = Vec::new();
                for mut handle in handles {
                    match handle.join(&cx).await {
                        Ok(outcome) => subsystems.push(outcome),
                        Err(join_error) => subsystems.push(SubsystemOutcome {
                            name: "<join-failed>".to_string(),
                            obligations_clean: false,
                            abandoned: vec![format!("join error: {join_error:?}")],
                        }),
                    }
                }
                Ok(ShutdownReceipt {
                    subsystems,
                    boot_ms,
                    shutdown_ms: shutdown_start.elapsed().as_millis(),
                    recovered_from_unclean,
                })
            })
            .await
    });

    // Clean shutdown removes the marker ONLY when the receipt is clean —
    // an unclean receipt leaves the evidence in place.
    if let (Some(marker), Ok(receipt)) = (&options.boot_marker, &result)
        && receipt.clean()
        && std::fs::remove_file(marker).is_err()
    {
        // Marker removal failure is loud in logs but not fatal.
        eprintln!(
            "{{\"v\":1,\"kind\":\"rabsd-log\",\"warn\":\"boot marker not removable\",\"path\":\"{}\"}}",
            marker.display()
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(run_for_ms: u64) -> DaemonRunOptions {
        DaemonRunOptions {
            run_for: Some(Duration::from_millis(run_for_ms)),
            boot_marker: None,
            behavior: [SubsystemBehavior::Clean; 4],
            edge_work: None,
        }
    }

    #[test]
    fn boots_runs_and_shuts_down_obligation_clean() {
        let receipt = run_daemon(options(30)).expect("daemon runs");
        assert!(receipt.clean(), "{receipt:?}");
        assert_eq!(receipt.subsystems.len(), 4);
        assert!(receipt.boot_ms < 100, "boot took {}ms", receipt.boot_ms);
        assert!(
            receipt.shutdown_ms < 100,
            "shutdown took {}ms",
            receipt.shutdown_ms
        );
        let names: Vec<&str> = receipt.subsystems.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, DAEMON_SUBSYSTEMS.to_vec(), "model order held live");
    }

    #[test]
    fn abandoned_obligation_is_reported_with_reason_never_dropped() {
        let mut opts = options(30);
        opts.behavior[1] = SubsystemBehavior::HoldObligationOpen; // coord
        let receipt = run_daemon(opts).expect("daemon runs");
        assert!(!receipt.clean());
        let coord = &receipt.subsystems[1];
        assert_eq!(coord.name, "coord");
        assert!(!coord.obligations_clean);
        assert!(coord.abandoned[0].contains("ProcessGroupDrain"));
        // The receipt names EXACTLY the guilty subsystem.
        assert!(receipt.subsystems[0].obligations_clean);
        assert!(receipt.subsystems[2].obligations_clean);
    }

    #[test]
    fn boot_marker_crash_evidence_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("rabsd.boot");
        // First clean run: marker created then removed.
        let mut opts = options(20);
        opts.boot_marker = Some(marker.clone());
        let receipt = run_daemon(opts).expect("run 1");
        assert!(!receipt.recovered_from_unclean);
        assert!(!marker.exists(), "clean shutdown removes the marker");
        // Simulate kill -9: marker left behind by a dead incarnation.
        std::fs::write(&marker, "pid=99999\n").unwrap();
        let mut opts = options(20);
        opts.boot_marker = Some(marker.clone());
        let receipt = run_daemon(opts).expect("run 2");
        assert!(
            receipt.recovered_from_unclean,
            "boot must report the unclean prior incarnation"
        );
        // Unclean-receipt runs KEEP the marker (evidence preserved).
        let mut opts_unclean = options(20);
        let marker2 = dir.path().join("rabsd2.boot");
        opts_unclean.boot_marker = Some(marker2.clone());
        opts_unclean.behavior[3] = SubsystemBehavior::HoldObligationOpen;
        let receipt = run_daemon(opts_unclean).expect("run 3");
        assert!(!receipt.clean());
        assert!(marker2.exists(), "unclean receipt preserves the evidence");
    }

    #[test]
    fn receipt_json_line_is_wellformed_and_carries_the_accounting() {
        let mut opts = options(20);
        opts.behavior[0] = SubsystemBehavior::HoldObligationOpen;
        let receipt = run_daemon(opts).expect("daemon runs");
        let line = receipt.to_json_line();
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains("\"clean\":false"));
        assert!(line.contains("\"name\":\"edge\""));
        assert!(line.contains("abandoned"));
        assert_eq!(line.lines().count(), 1, "one JSON line");
    }

    #[test]
    fn model_and_subsystem_constant_agree() {
        let spec = daemon_region_spec();
        assert_eq!(spec.name, "rabsd");
        let model: Vec<&str> = spec.children.iter().map(|c| c.name).collect();
        assert_eq!(model, DAEMON_SUBSYSTEMS.to_vec());
    }
}
