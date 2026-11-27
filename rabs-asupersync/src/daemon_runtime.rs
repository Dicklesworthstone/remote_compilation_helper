//! The daemon runtime island (bead S1 / bridge plan Phase S; MILESTONE
//! M2 keystone). FIRST real use of the asupersync runtime in this
//! workspace: everything before this module modeled regions and
//! obligations; this module BOOTS them.
//!
//! The bridge plan's integration contract, held here:
//!
//! - Regions own lifetimes. Every subsystem is a region-owned task
//!   spawned through Cx::spawn; there are no detached tasks. The root
//!   supervises terminal results while running and joins every owner
//!   before returning, including after panic or partial startup failure.
//! - Cx is the only capability channel. Subsystem bodies receive
//!   their Cx from the runtime; nothing reaches for ambient state.
//! - Obligations are typed completions. Each subsystem holds an
//!   ObligationSet; an owner that exits without reporting completion is
//!   attributed by name, never silently dropped. The region-tree model
//!   is asserted against the live spawn ledger at boot.
//! - Crash evidence survives. A boot marker prevents the evidence-loss
//!   mode "kill -9 erases what was running". Named subsystem crashpacks
//!   accompany nonclean shutdown receipts. A marker found at boot means
//!   the prior incarnation died unclean.

use crate::crashpack::{Crashpack, RedactedContext};
use crate::obligations::{ObligationKind, ObligationSet};
use crate::region_tree::{Attribution, RegionSpec};
use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::signal::ShutdownController;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

/// The daemon's subsystem regions, in spawn order (plan §12).
pub const DAEMON_SUBSYSTEMS: [&str; 4] = ["edge", "coord", "telemetry", "janitor"];

/// The MODEL of the daemon region tree (spec side of the boot-time
/// spec-vs-implementation assertion).
#[must_use]
pub fn daemon_region_spec() -> RegionSpec {
    RegionSpec {
        name: "rabsd",
        introduces: Attribution::default(),
        children: DAEMON_SUBSYSTEMS
            .iter()
            .map(|name| RegionSpec {
                name,
                introduces: Attribution::default(),
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
    /// Evidence from this actual subsystem owner. A daemon failure does not
    /// invent action/attempt identities, quarantine, or permission to retry.
    pub crashpack: Option<Crashpack>,
}

/// The shutdown receipt, generated from runtime accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReceipt {
    /// Per-subsystem outcomes in spawn order.
    pub subsystems: Vec<SubsystemOutcome>,
    /// Startup-origin-to-subsystem-spawn duration, including caller setup.
    /// This does not establish that an edge socket has started accepting.
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
                    "{{\"name\":{},\"obligations_clean\":{},\"abandoned\":[{}],\"crashpack\":{}}}",
                    json_string(&s.name),
                    s.obligations_clean,
                    s.abandoned
                        .iter()
                        .map(|reason| json_string(reason))
                        .collect::<Vec<_>>()
                        .join(","),
                    s.crashpack
                        .as_ref()
                        .map_or_else(|| "null".into(), crashpack_json)
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
/// Returning Ok before shutdown is also a service failure.
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
    /// Startup origin captured before configuration and persistent-store setup.
    /// Defaults to option construction for embedded callers; the binary passes
    /// its main-entry timestamp so CAS reconciliation is included.
    pub boot_started_at: Instant,
    /// Auto-trigger shutdown after this duration (None = wait for
    /// SIGTERM/SIGINT via the asupersync signal listener).
    pub run_for: Option<Duration>,
    /// Boot marker path (crash-evidence control). None disables.
    pub boot_marker: Option<std::path::PathBuf>,
    /// Per-subsystem behavior override (lab); defaults to Clean.
    pub behavior: [SubsystemBehavior; 4],
    /// Real work for the edge region (S3+: the UDS server). None =
    /// idle skeleton.
    pub edge_work: Option<SubsystemWork>,
    /// Real work for the coord region (S6+: the live coordinator).
    /// None = idle skeleton.
    pub coord_work: Option<SubsystemWork>,
    /// Real work for the janitor region (W1/Phase 1: the on-disk
    /// rabs-cas byte store + quota/GC owner). None = idle skeleton.
    pub janitor_work: Option<SubsystemWork>,
}

impl std::fmt::Debug for DaemonRunOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonRunOptions")
            .field("boot_started_at", &self.boot_started_at)
            .field("run_for", &self.run_for)
            .field("boot_marker", &self.boot_marker)
            .field("behavior", &self.behavior)
            .field("edge_work", &self.edge_work.is_some())
            .field("coord_work", &self.coord_work.is_some())
            .field("janitor_work", &self.janitor_work.is_some())
            .finish()
    }
}

impl Default for DaemonRunOptions {
    fn default() -> Self {
        Self {
            boot_started_at: Instant::now(),
            run_for: None,
            boot_marker: None,
            behavior: [SubsystemBehavior::Clean; 4],
            edge_work: None,
            coord_work: None,
            janitor_work: None,
        }
    }
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for c in value.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            c if u32::from(c) < 0x20 => escaped.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn crashpack_json(pack: &Crashpack) -> String {
    let attribution = [
        ("coordinator_authority", &pack.attribution.coordinator_authority),
        ("build_operation", &pack.attribution.build_operation),
        ("action_key", &pack.attribution.action_key),
        ("action_generation", &pack.attribution.action_generation),
        ("attempt", &pack.attribution.attempt),
        ("lease", &pack.attribution.lease),
        ("worker_boot_generation", &pack.attribution.worker_boot_generation),
    ]
    .into_iter()
    .map(|(name, value)| {
        format!(
            "{}:{}",
            json_string(name),
            value
                .as_ref()
                .map_or_else(|| "null".into(), |value| json_string(value))
        )
    })
    .collect::<Vec<_>>()
    .join(",");
    let obligations = pack
        .outstanding_obligations
        .iter()
        .map(|kind| json_string(&format!("{kind:?}")))
        .collect::<Vec<_>>()
        .join(",");
    let events = pack
        .recent_events
        .iter()
        .map(|event| json_string(event))
        .collect::<Vec<_>>()
        .join(",");
    let context = pack
        .context
        .iter()
        .map(|entry| {
            format!(
                "{{\"key\":{},\"value\":{}}}",
                json_string(&entry.key),
                json_string(&entry.value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"failure\":{},\"attribution\":{{{attribution}}},\"outstanding_obligations\":[{obligations}],\"recent_events\":[{events}],\"context\":[{context}]}}",
        json_string(&pack.failure),
    )
}

/// One JSON line announcing a subsystem whose work failed.
fn failure_line(name: &str, reason: &str) -> String {
    format!(
        "{{\"v\":1,\"kind\":\"rabsd-subsystem-failed\",\"subsystem\":{},\"reason\":{}}}",
        json_string(name),
        json_string(reason),
    )
}

fn failure_evidence(name: &str, reason: &str, obligations: &ObligationSet) -> Crashpack {
    let outstanding_obligations = match obligations.may_close_region() {
        Err(crate::obligations::ObligationError::Unresolved(kinds)) => kinds,
        _ => Vec::new(),
    };
    Crashpack {
        failure: reason.to_owned(),
        attribution: Attribution::default(),
        outstanding_obligations,
        recent_events: vec!["subsystem admitted".into(), "subsystem failed".into()],
        context: vec![RedactedContext {
            key: "region".into(),
            value: format!("rabsd/{name}"),
        }],
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
    controller: Arc<ShutdownController>,
) -> SubsystemOutcome {
    cx.trace(&format!("rabsd subsystem {name} ready"));
    let mut obligations = ObligationSet::default();
    obligations.open(lifetime_obligation(name));

    // Record early return at the owner boundary, before another subsystem or
    // an external signal can race with the parent's observation of this join.
    let work_result = match work {
        Some(work) => work(cx.clone(), shutdown).await,
        None => {
            shutdown.wait().await;
            Ok(())
        }
    };
    let work_result = if work_result.is_ok() && !controller.is_shutting_down() {
        Err("subsystem returned before shutdown".into())
    } else {
        work_result
    };
    if let Err(reason) = &work_result {
        // Stop admission before reporting the failure. A dead listener or
        // coordinator must not wait indefinitely for an external signal.
        controller.shutdown();
        let _ = writeln!(std::io::stderr().lock(), "{}", failure_line(name, reason));
    }

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
        crashpack: (!obligations_clean)
            .then(|| failure_evidence(name, &abandoned.join("; "), &obligations)),
        abandoned,
    }
}

fn joined_subsystem(
    name: &'static str,
    joined: Result<SubsystemOutcome, asupersync::runtime::JoinError>,
    controller: &ShutdownController,
) -> SubsystemOutcome {
    match joined {
        Ok(outcome) => outcome,
        Err(error) => {
            // The runtime contains the panic and publishes a typed terminal
            // result. Do not replace the subsystem or infer retry authority.
            // Stop new work and retain every sibling owner until its join.
            controller.shutdown();
            let reason = format!("subsystem join failed: {error}");
            let mut obligations = ObligationSet::default();
            // This owner never reported its lifetime obligation complete.
            // The evidence does not infer which child effects are still live.
            obligations.open(lifetime_obligation(name));
            let _ = writeln!(std::io::stderr().lock(), "{}", failure_line(name, &reason));
            SubsystemOutcome {
                name: name.into(),
                obligations_clean: false,
                crashpack: Some(failure_evidence(name, &reason, &obligations)),
                abandoned: vec![reason],
            }
        }
    }
}

/// Drive a top-level future on a standalone runtime outside any active
/// asupersync task.
///
/// # Panics
/// Panics if Cx::current().is_some(), enforcing the nested-runtime
/// prohibition dynamically as well as statically.
pub fn block_on_top_level<F: std::future::Future>(
    runtime: &asupersync::runtime::Runtime,
    future: F,
) -> F::Output {
    assert!(
        Cx::current().is_none(),
        "nested runtime entry is forbidden inside an active asupersync task"
    );
    runtime.block_on(future)
}

/// Boot the runtime island, run the subsystem regions, shut down
/// cleanly, and return the receipt generated from the accounting.
pub fn run_daemon(options: DaemonRunOptions) -> Result<ShutdownReceipt, DaemonError> {
    let controller = Arc::new(ShutdownController::new());
    if options.run_for.is_none() {
        controller.listen_for_signals();
    }
    run_daemon_controlled(options, controller)
}

/// Run an embedded daemon whose lifetime is owned by its caller. The caller
/// retains the controller, requests shutdown after its operation ends, and
/// joins this call before releasing any operation inputs or output directories.
/// Unlike run_daemon, this entry point does not install a process-wide signal
/// listener. The optional timed shutdown is owned by the root future.
pub fn run_daemon_controlled(
    options: DaemonRunOptions,
    controller: Arc<ShutdownController>,
) -> Result<ShutdownReceipt, DaemonError> {
    let boot_start = options.boot_started_at;

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

    let run_for = options.run_for;
    let behavior = options.behavior;
    let mut edge_work = options.edge_work;
    let mut coord_work = options.coord_work;
    let mut janitor_work = options.janitor_work;
    let root_controller = Arc::clone(&controller);
    let handle = runtime.handle();
    let result: Result<ShutdownReceipt, DaemonError> = runtime.block_on(async move {
        handle
            .spawn(async move {
                let cx = Cx::current().expect("runtime task carries a Cx");
                cx.trace("rabsd root region up");
                // No sleeping OS thread retains this incarnation after an
                // early failure or external shutdown. Dropping the root drops
                // its timer registration as well.
                let mut auto_shutdown = run_for.map(|delay| {
                    Box::pin(asupersync::time::sleep(
                        asupersync::time::wall_now(),
                        delay,
                    ))
                });

                let mut handles = Vec::new();
                let mut spawned: Vec<String> = Vec::new();
                let mut boot_error = None;
                for (index, &name) in DAEMON_SUBSYSTEMS.iter().enumerate() {
                    let shutdown = root_controller.subscribe();
                    let subsystem_behavior = behavior[index];
                    let work = match name {
                        "edge" => edge_work.take(),
                        "coord" => coord_work.take(),
                        "janitor" => janitor_work.take(),
                        _ => None,
                    };
                    let controller = Arc::clone(&root_controller);
                    match cx.spawn(move |cx| {
                        subsystem_body(name, cx, shutdown, subsystem_behavior, work, controller)
                    }) {
                        Ok(handle) => {
                            spawned.push(name.to_string());
                            handles.push((name, handle));
                        }
                        Err(error) => {
                            boot_error = Some(DaemonError::SubsystemSpawn {
                                name,
                                error: format!("{error:?}"),
                            });
                            root_controller.shutdown();
                            break;
                        }
                    }
                }

                let expected: Vec<String> = daemon_region_spec()
                    .children
                    .iter()
                    .map(|c| c.name.to_string())
                    .collect();
                if boot_error.is_none() && expected != spawned {
                    boot_error = Some(DaemonError::ModelDivergence {
                        expected,
                        actual: spawned,
                    });
                    root_controller.shutdown();
                }

                let boot_ms = boot_start.elapsed().as_millis();
                if boot_error.is_none() {
                    cx.trace("rabsd ready");
                }

                let mut shutdown_rx = root_controller.subscribe();
                let mut shutdown = pin!(shutdown_rx.wait());
                let mut shutdown_start = None;
                let mut outcomes = vec![None; handles.len()];
                // Observe terminal results while running, not only after
                // shutdown. poll_join retains each wake registration; building
                // and dropping a fresh join future per poll would cancel work
                // or retire its only wake source.
                poll_fn(|task| {
                    if shutdown_start.is_none() {
                        if shutdown.as_mut().poll(task).is_ready() {
                            shutdown_start = Some(Instant::now());
                        } else if auto_shutdown
                            .as_mut()
                            .is_some_and(|timer| timer.as_mut().poll(task).is_ready())
                        {
                            root_controller.shutdown();
                            shutdown_start = Some(Instant::now());
                        }
                    }

                    let mut pending = false;
                    for ((name, handle), outcome) in handles.iter_mut().zip(&mut outcomes) {
                        if outcome.is_some() {
                            continue;
                        }
                        match handle.poll_join(task) {
                            Poll::Ready(joined) => {
                                let terminal = joined_subsystem(name, joined, &root_controller);
                                if !terminal.obligations_clean {
                                    root_controller.shutdown();
                                    shutdown_start.get_or_insert_with(Instant::now);
                                }
                                *outcome = Some(terminal);
                            }
                            Poll::Pending => pending = true,
                        }
                    }

                    if shutdown_start.is_some() {
                        auto_shutdown = None;
                    }
                    if pending {
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;

                // This also runs after partial startup failure: all admitted
                // owners were signalled and joined before returning the error.
                if let Some(error) = boot_error {
                    return Err(error);
                }
                Ok(ShutdownReceipt {
                    subsystems: outcomes
                        .into_iter()
                        .map(|outcome| outcome.expect("every subsystem joined"))
                        .collect(),
                    boot_ms,
                    shutdown_ms: shutdown_start.map_or(0, |started| started.elapsed().as_millis()),
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
            "{{\"v\":1,\"kind\":\"rabsd-log\",\"warn\":\"boot marker not removable\",\"path\":{}}}",
            json_string(&marker.display().to_string())
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn options(run_for_ms: u64) -> DaemonRunOptions {
        DaemonRunOptions {
            boot_started_at: Instant::now(),
            run_for: Some(Duration::from_millis(run_for_ms)),
            boot_marker: None,
            behavior: [SubsystemBehavior::Clean; 4],
            edge_work: None,
            coord_work: None,
            janitor_work: None,
        }
    }

    fn failure_run(opts: DaemonRunOptions) -> ShutdownReceipt {
        let controller = Arc::new(ShutdownController::new());
        let owned_controller = Arc::clone(&controller);
        let (sender, receiver) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            let _ = sender.send(run_daemon_controlled(opts, owned_controller));
        });
        let result = receiver.recv_timeout(Duration::from_secs(20));
        if result.is_err() {
            // A regression may wait forever for shutdown. Signal it so the
            // test still owns and joins the runtime before failing.
            controller.shutdown();
        }
        owner.join().expect("daemon owner returns without panicking");
        result
            .expect("subsystem failure must stop the daemon without an external signal")
            .expect("daemon runs")
    }

    fn draining_work(drained: Arc<AtomicBool>) -> SubsystemWork {
        Box::new(move |_cx, mut shutdown| {
            Box::pin(async move {
                shutdown.wait().await;
                asupersync::time::sleep(
                    asupersync::time::wall_now(),
                    Duration::from_millis(30),
                )
                .await;
                drained.store(true, Ordering::Release);
                Ok(())
            })
        })
    }

    #[test]
    fn boot_timing_includes_pre_runtime_setup() {
        let opts = options(30);
        // Real pre-runtime work must not disappear when run_daemon starts.
        std::thread::sleep(Duration::from_millis(40));
        let setup_ms = opts.boot_started_at.elapsed().as_millis();
        let receipt = run_daemon(opts).expect("daemon runs after setup");
        assert!(receipt.clean(), "{receipt:?}");
        assert!(
            receipt.boot_ms >= setup_ms,
            "boot {}ms omitted setup {setup_ms}ms",
            receipt.boot_ms
        );
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
        assert!(receipt.subsystems.iter().all(|s| s.crashpack.is_none()));
    }

    #[test]
    fn a_failed_subsystem_stops_the_daemon_instead_of_idling_silently() {
        // No run_for and no signal listener: before, nothing would ever end
        // this run once the edge refused its endpoint.
        let mut opts = options(0);
        opts.run_for = None;
        opts.edge_work = Some(Box::new(|_cx, _shutdown| {
            Box::pin(async { Err("endpoint /tmp/x.sock: unsafe \"parent\"\nmode 1777".to_owned()) })
        }));
        let receipt = failure_run(opts);
        assert!(!receipt.clean());
        let edge = &receipt.subsystems[0];
        assert_eq!(edge.name, "edge");
        assert!(edge.abandoned[0].contains("unsafe"), "{edge:?}");
        assert!(receipt.subsystems[1..].iter().all(|s| s.obligations_clean));
        // The announcement is one valid JSON object, whatever the reason holds.
        let line = failure_line("edge", "a \"quoted\" \\ path\nnext");
        assert_eq!(
            line,
            "{\"v\":1,\"kind\":\"rabsd-subsystem-failed\",\"subsystem\":\"edge\",\
             \"reason\":\"a \\\"quoted\\\" \\\\ path\\u000anext\"}"
        );
    }

    #[test]
    fn a_panicked_subsystem_stops_without_a_signal_and_drains_siblings() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("panicked.boot");
        let drained = Arc::new(AtomicBool::new(false));
        let mut opts = options(0);
        opts.run_for = None;
        opts.boot_marker = Some(marker.clone());
        opts.edge_work = Some(Box::new(|_cx, _shutdown| {
            Box::pin(async {
                asupersync::time::sleep(
                    asupersync::time::wall_now(),
                    Duration::from_millis(10),
                )
                .await;
                panic!("deliberate subsystem panic");
            })
        }));
        opts.coord_work = Some(draining_work(Arc::clone(&drained)));
        let receipt = failure_run(opts);
        assert!(drained.load(Ordering::Acquire), "sibling still owns its work");
        assert!(!receipt.clean(), "{receipt:?}");
        assert!(marker.exists(), "panic must preserve crash-recovery marker");
        assert_eq!(receipt.subsystems.len(), DAEMON_SUBSYSTEMS.len());
        let edge = &receipt.subsystems[0];
        assert_eq!(edge.name, "edge");
        assert!(edge.abandoned[0].contains("deliberate subsystem panic"));
        let pack = edge.crashpack.as_ref().expect("actual panic evidence");
        assert!(pack.failure.contains("deliberate subsystem panic"));
        assert_eq!(pack.attribution, Attribution::default());
        assert_eq!(
            pack.outstanding_obligations,
            vec![ObligationKind::ProcessGroupDrain]
        );
        assert_eq!(
            pack.context,
            vec![RedactedContext {
                key: "region".into(),
                value: "rabsd/edge".into(),
            }]
        );
        assert!(receipt.subsystems[1..].iter().all(|s| s.obligations_clean));
    }

    #[test]
    fn a_panicking_work_factory_is_also_supervised() {
        let drained = Arc::new(AtomicBool::new(false));
        let mut opts = options(0);
        opts.run_for = None;
        opts.coord_work = Some(Box::new(|_cx, _shutdown| {
            panic!("work factory failed before returning its future");
        }));
        opts.janitor_work = Some(draining_work(Arc::clone(&drained)));
        let receipt = failure_run(opts);
        assert!(drained.load(Ordering::Acquire));
        assert!(!receipt.clean());
        let coord = &receipt.subsystems[1];
        assert_eq!(coord.name, "coord");
        assert!(coord.abandoned[0].contains("work factory failed"));
        assert!(coord.crashpack.is_some());
        for (index, outcome) in receipt.subsystems.iter().enumerate() {
            assert_eq!(outcome.name, DAEMON_SUBSYSTEMS[index]);
            assert_eq!(outcome.obligations_clean, index != 1);
        }
    }

    #[test]
    fn early_success_is_a_service_failure_not_a_silent_idle_daemon() {
        let drained = Arc::new(AtomicBool::new(false));
        let mut opts = options(0);
        opts.run_for = None;
        opts.edge_work = Some(Box::new(|_cx, _shutdown| Box::pin(async { Ok(()) })));
        opts.coord_work = Some(draining_work(Arc::clone(&drained)));
        let receipt = failure_run(opts);
        assert!(drained.load(Ordering::Acquire));
        assert!(!receipt.clean());
        let edge = &receipt.subsystems[0];
        assert_eq!(edge.name, "edge");
        assert!(edge.abandoned[0].contains("returned before shutdown"));
        assert!(receipt.subsystems[1..].iter().all(|s| s.obligations_clean));
    }

    #[test]
    fn shutdown_panic_does_not_skip_later_sibling_drains() {
        let drained = Arc::new(AtomicBool::new(false));
        let mut opts = options(10);
        opts.edge_work = Some(Box::new(|_cx, mut shutdown| {
            Box::pin(async move {
                shutdown.wait().await;
                panic!("panic while closing listener");
            })
        }));
        opts.janitor_work = Some(draining_work(Arc::clone(&drained)));
        let receipt = failure_run(opts);
        assert!(drained.load(Ordering::Acquire));
        assert!(!receipt.clean());
        assert_eq!(receipt.subsystems[0].name, "edge");
        assert!(receipt.subsystems[0].abandoned[0].contains("closing listener"));
        assert!(receipt.subsystems[1..].iter().all(|s| s.obligations_clean));
    }

    #[test]
    fn independent_failures_are_all_named_before_return() {
        let drained = Arc::new(AtomicBool::new(false));
        let mut opts = options(0);
        opts.run_for = None;
        opts.edge_work = Some(Box::new(|_cx, mut shutdown| {
            Box::pin(async move {
                shutdown.wait().await;
                panic!("edge drain failed");
            })
        }));
        opts.coord_work = Some(Box::new(|_cx, _shutdown| {
            Box::pin(async { Err("coordinator authority lost".into()) })
        }));
        opts.janitor_work = Some(draining_work(Arc::clone(&drained)));
        let receipt = failure_run(opts);
        assert!(drained.load(Ordering::Acquire));
        assert!(!receipt.clean());
        assert!(!receipt.subsystems[0].obligations_clean);
        assert!(!receipt.subsystems[1].obligations_clean);
        assert!(receipt.subsystems[0].abandoned[0].contains("edge drain failed"));
        assert!(receipt.subsystems[1].abandoned[0].contains("authority lost"));
        assert!(receipt.subsystems[2..].iter().all(|s| s.obligations_clean));
    }

    #[test]
    fn early_failure_drops_the_owned_shutdown_timer_and_controller() {
        let controller = Arc::new(ShutdownController::new());
        let weak = Arc::downgrade(&controller);
        let mut opts = options(86_400_000);
        opts.edge_work = Some(Box::new(|_cx, _shutdown| {
            Box::pin(async { Err("startup failed".into()) })
        }));
        let receipt =
            run_daemon_controlled(opts, Arc::clone(&controller)).expect("daemon returns");
        assert!(!receipt.clean());
        drop(controller);
        assert!(
            weak.upgrade().is_none(),
            "a detached timer must not retain an ended daemon for a day"
        );
    }

    #[test]
    fn external_shutdown_drops_a_later_timer_without_marking_clean_work_failed() {
        let controller = Arc::new(ShutdownController::new());
        let weak = Arc::downgrade(&controller);
        controller.shutdown();
        let receipt = run_daemon_controlled(options(86_400_000), Arc::clone(&controller))
            .expect("already-requested shutdown");
        assert!(receipt.clean(), "{receipt:?}");
        drop(controller);
        assert!(weak.upgrade().is_none());
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
    fn failure_receipt_preserves_quotes_backslashes_and_control_characters() {
        assert_eq!(
            json_string("a \"quoted\" \\ path\n\t\0\rnext"),
            "\"a \\\"quoted\\\" \\\\ path\\u000a\\u0009\\u0000\\u000dnext\""
        );
        let mut opts = options(0);
        opts.run_for = None;
        opts.edge_work = Some(Box::new(|_cx, _shutdown| {
            Box::pin(async { Err("failure \"detail\" \\ path\nnext".into()) })
        }));
        let receipt = failure_run(opts);
        let line = receipt.to_json_line();
        assert_eq!(line.lines().count(), 1, "failure must stay one JSON record");
        assert!(line.contains(r#""abandoned":["work failed: failure \"detail\" \\ path\u000anext"]"#));
        assert!(line.contains(r#""failure":"work failed: failure \"detail\" \\ path\u000anext""#));
        assert!(line.contains(r#""context":[{"key":"region","value":"rabsd/edge"}]"#));
    }

    #[test]
    fn model_and_subsystem_constant_agree() {
        let spec = daemon_region_spec();
        assert_eq!(spec.name, "rabsd");
        let model: Vec<&str> = spec.children.iter().map(|c| c.name).collect();
        assert_eq!(model, DAEMON_SUBSYSTEMS.to_vec());
    }
}
