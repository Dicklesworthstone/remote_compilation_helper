//! The dependency shadow-comparison pipeline (bead K008; trust-ladder
//! Stage 2 driving Stage 3's sampling switch).
//!
//! [`crate::StockPath`] replays the authoritative stock execution;
//! [`ShadowServingPath`] replays the RABS dependency-serving CANDIDATE
//! path: a [`ShadowServingBackend`] decides per invocation whether the
//! request would be SERVED from the published cache or executed
//! PRIVATELY as fresh shadow evidence (the sampling gate itself lives
//! store-side in `rabs-cas::serving_sample_gate`; here it is a pluggable
//! decision so this crate stays protocol-only).
//!
//! [`run_shadow_pipeline`] automates the whole comparison over a B002
//! corpus: stock vs candidate per record, typed
//! [`crate::DivergenceRecord`] rows, skips first-class — and classifies
//! every divergence by what it means downstream:
//!
//! - a SERVED result that diverges from stock is an instant-quarantine
//!   input (`quarantine_required`, consumed by
//!   `rabs_cas::serving_sample_gate::quarantine_served_divergence`);
//! - a PRIVATELY EXECUTED result that diverges from stock counts in
//!   `private_divergences` (evidence quality problem, not a serving
//!   soundness incident).
//!
//! Availability is still a difference, never a divergence: a cache HIT
//! with byte-identical results is the goal state.

use rabs_protocol::invocation_record::NormalizedOutcome;
use rabs_protocol::redaction::correlation_hash;

use crate::{
    Availability, ExecutionPath, PathObservation, ReplayCommand, SessionReport, StockPath,
    replay_session,
};

/// Path name recorded for the candidate side of the shadow comparison.
pub const SHADOW_SERVING_PATH_NAME: &str = "shadow-sampled-serving";

/// Per-invocation serving decision (the sampling switch, abstracted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingDecision {
    /// Attempt to serve from the published cache.
    ServeFromCache,
    /// Execute privately as fresh shadow evidence.
    ExecutePrivately,
}

/// The authoritative cached result a backend serves for one invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedObservation {
    /// Cached terminal outcome.
    pub outcome: NormalizedOutcome,
    /// Correlation digest over cached stdout bytes.
    pub stdout_digest: u64,
    /// Correlation digest over cached stderr bytes.
    pub stderr_digest: u64,
}

/// Store-side serving logic behind the candidate path: the sampling
/// gate decision plus the cache lookup. Implementations keep this
/// crate free of storage dependencies.
pub trait ShadowServingBackend {
    /// The sampling-gate decision for one invocation.
    fn decide(&mut self, invocation: &ReplayCommand) -> ServingDecision;
    /// The authoritative cached observation for a serve decision;
    /// `None` is a typed miss that falls back to private execution.
    fn served_observation(
        &mut self,
        invocation: &ReplayCommand,
    ) -> Option<CachedObservation>;
}

/// REALLY execute the invocation (`sh -c` in the recorded cwd), shared
/// by the stock path and every private-execution fallback so stock and
/// candidates observe under identical mechanics.
pub(crate) fn really_execute(path_name: &str, invocation: &ReplayCommand) -> PathObservation {
    let started = std::time::Instant::now();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&invocation.command)
        .current_dir(&invocation.cwd)
        .output();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match output {
        Ok(output) => {
            #[cfg(unix)]
            let outcome = {
                use std::os::unix::process::ExitStatusExt;
                output.status.code().map_or_else(
                    || NormalizedOutcome::Signaled(output.status.signal().unwrap_or(0)),
                    NormalizedOutcome::Exited,
                )
            };
            #[cfg(not(unix))]
            let outcome = NormalizedOutcome::Exited(output.status.code().unwrap_or(-1));
            PathObservation {
                path_name: path_name.to_owned(),
                availability: Availability::Executed,
                outcome: Some(outcome),
                stdout_digest: correlation_hash(&output.stdout),
                stderr_digest: correlation_hash(&output.stderr),
                duration_ms,
            }
        }
        Err(_) => PathObservation {
            path_name: path_name.to_owned(),
            availability: Availability::Unavailable,
            outcome: None,
            stdout_digest: 0,
            stderr_digest: 0,
            duration_ms,
        },
    }
}

/// The RABS dependency-serving candidate path: serve when the gate says
/// so and the cache has the entry; execute privately otherwise.
pub struct ShadowServingPath<'a> {
    backend: &'a mut dyn ShadowServingBackend,
}

impl std::fmt::Debug for ShadowServingPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowServingPath")
            .field("backend", &SHADOW_SERVING_PATH_NAME)
            .finish()
    }
}

impl<'a> ShadowServingPath<'a> {
    /// Wrap a serving backend as an executable path.
    #[must_use]
    pub fn new(backend: &'a mut dyn ShadowServingBackend) -> Self {
        Self { backend }
    }
}

impl ExecutionPath for ShadowServingPath<'_> {
    fn name(&self) -> &str {
        SHADOW_SERVING_PATH_NAME
    }

    fn execute(&mut self, invocation: &ReplayCommand) -> PathObservation {
        if self.backend.decide(invocation) == ServingDecision::ServeFromCache {
            if let Some(cached) = self.backend.served_observation(invocation) {
                return PathObservation {
                    path_name: SHADOW_SERVING_PATH_NAME.to_owned(),
                    availability: Availability::CacheHit,
                    outcome: Some(cached.outcome),
                    stdout_digest: cached.stdout_digest,
                    stderr_digest: cached.stderr_digest,
                    // Serving performs no tool work; the wall clock of
                    // a hit measures the lookup, reported as zero.
                    duration_ms: 0,
                };
            }
        }
        really_execute(SHADOW_SERVING_PATH_NAME, invocation)
    }
}

/// Session-level shadow-pipeline results: the raw comparison session
/// plus the divergence classification downstream gates act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowPipelineReport {
    /// Full stock-vs-candidate comparison session.
    pub session: SessionReport,
    /// Commands whose SERVED result diverged from authoritative stock —
    /// the instant-quarantine inputs.
    pub quarantine_required: Vec<String>,
    /// Divergences observed while executing privately (an evidence
    /// quality problem, never a serving incident).
    pub private_divergences: usize,
}

/// Run the shadow comparison across a whole B002 corpus: every parsed
/// record replays under stock and under the sampled-serving candidate;
/// rows classify into quarantine-required (served-and-diverged) versus
/// private divergences. Skipped records stay first-class in the inner
/// session report.
#[must_use]
pub fn run_shadow_pipeline(
    corpus_lines: &[&str],
    backend: &mut dyn ShadowServingBackend,
) -> ShadowPipelineReport {
    let mut stock = StockPath;
    let mut candidate = ShadowServingPath::new(backend);
    let session = replay_session(corpus_lines, &mut stock, &mut candidate);
    let mut quarantine_required = Vec::new();
    let mut private_divergences = 0_usize;
    for row in &session.rows {
        if !row.diverged() {
            continue;
        }
        if row.candidate_availability == Availability::CacheHit {
            quarantine_required.push(row.command.clone());
        } else {
            private_divergences += 1;
        }
    }
    ShadowPipelineReport {
        session,
        quarantine_required,
        private_divergences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn corpus_line(command: &str, code: i32) -> String {
        serde_json::json!({
            "argv_redacted": command.split(' ').collect::<Vec<&str>>(),
            "cwd_redacted": std::env::temp_dir().to_string_lossy(),
            "outcome_kind": "exited",
            "outcome_value": code,
            "duration_ms": 5_u64,
        })
        .to_string()
    }

    /// Configurable fake of the coordinator-side gate + cache.
    #[derive(Default)]
    struct FakeBackend {
        force_decision: Option<ServingDecision>,
        cache: HashMap<String, CachedObservation>,
    }

    impl ShadowServingBackend for FakeBackend {
        fn decide(&mut self, _invocation: &ReplayCommand) -> ServingDecision {
            self.force_decision
                .unwrap_or(ServingDecision::ServeFromCache)
        }

        fn served_observation(
            &mut self,
            invocation: &ReplayCommand,
        ) -> Option<CachedObservation> {
            self.cache.get(&invocation.command).copied()
        }
    }

    fn cached_for(stdout: &[u8], code: i32) -> CachedObservation {
        CachedObservation {
            outcome: NormalizedOutcome::Exited(code),
            stdout_digest: correlation_hash(stdout),
            stderr_digest: correlation_hash(b""),
        }
    }

    #[test]
    fn private_execution_matches_stock_without_quarantine() {
        let lines = [corpus_line("true", 0), corpus_line("false", 1)];
        let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let mut backend = FakeBackend {
            force_decision: Some(ServingDecision::ExecutePrivately),
            cache: HashMap::new(),
        };
        let report = run_shadow_pipeline(&line_refs, &mut backend);
        assert_eq!(report.session.rows.len(), 2);
        assert_eq!(report.session.divergences(), 0);
        assert!(report.quarantine_required.is_empty());
        assert_eq!(report.private_divergences, 0);
        assert!(report.session.rows.iter().all(|row| {
            row.candidate_availability == Availability::Executed
                && row.candidate_path == SHADOW_SERVING_PATH_NAME
        }));
    }

    #[test]
    fn served_hits_agree_and_classify_as_cache_hits() {
        let line = corpus_line("echo k008-shadow", 0);
        let mut backend = FakeBackend {
            force_decision: Some(ServingDecision::ServeFromCache),
            cache: HashMap::from([(
                "echo k008-shadow".to_owned(),
                cached_for(b"k008-shadow\n", 0),
            )]),
        };
        let report = run_shadow_pipeline(std::slice::from_ref(&line.as_str()), &mut backend);
        assert_eq!(report.session.rows.len(), 1);
        let row = &report.session.rows[0];
        assert_eq!(row.candidate_availability, Availability::CacheHit);
        assert!(!row.diverged());
        assert_eq!(row.candidate_duration_ms, 0);
        assert!(report.quarantine_required.is_empty());
    }

    #[test]
    fn divergent_serve_becomes_instant_quarantine_input() {
        let line = corpus_line("echo k008-diverge", 0);

        // A wrong OUTCOME alone quarantines.
        let wrong_outcome = CachedObservation {
            outcome: NormalizedOutcome::Exited(1),
            stdout_digest: correlation_hash(b"k008-diverge\n"),
            stderr_digest: correlation_hash(b""),
        };
        let mut backend = FakeBackend {
            force_decision: Some(ServingDecision::ServeFromCache),
            cache: HashMap::from([("echo k008-diverge".to_owned(), wrong_outcome)]),
        };
        let report = run_shadow_pipeline(std::slice::from_ref(&line.as_str()), &mut backend);
        assert!(report.session.rows[0].diverged());
        assert_eq!(
            report.quarantine_required,
            vec!["echo k008-diverge".to_owned()]
        );
        assert_eq!(report.private_divergences, 0);

        // A wrong STDOUT digest alone also quarantines (byte compare).
        let wrong_stdout = CachedObservation {
            outcome: NormalizedOutcome::Exited(0),
            stdout_digest: correlation_hash(b"different"),
            stderr_digest: correlation_hash(b""),
        };
        let mut backend = FakeBackend {
            force_decision: Some(ServingDecision::ServeFromCache),
            cache: HashMap::from([("echo k008-diverge".to_owned(), wrong_stdout)]),
        };
        let report = run_shadow_pipeline(std::slice::from_ref(&line.as_str()), &mut backend);
        assert_eq!(report.quarantine_required.len(), 1);
    }

    #[test]
    fn serve_miss_falls_back_to_private_execution() {
        let line = corpus_line("true", 0);
        let mut backend = FakeBackend {
            force_decision: Some(ServingDecision::ServeFromCache),
            cache: HashMap::new(), // miss
        };
        let report = run_shadow_pipeline(std::slice::from_ref(&line.as_str()), &mut backend);
        let row = &report.session.rows[0];
        assert_eq!(row.candidate_availability, Availability::Executed);
        assert!(!row.diverged());
        assert!(report.quarantine_required.is_empty());
    }

    #[test]
    fn skipped_records_stay_first_class_in_the_session() {
        let lines = ["{\"argv_redacted\": [\"cmd\", \"REDACTED\"]}"];
        let mut backend = FakeBackend::default();
        let report = run_shadow_pipeline(&lines, &mut backend);
        assert_eq!(report.session.rows.len(), 0);
        assert_eq!(report.session.skipped_redacted, 1);
    }
}
