//! Divergence minimizer: smallest reproducing invocation + input
//! manifest (bead B011; feeds the deterministic lab, Epic T).
//!
//! A diverging replay from a real corpus is usually huge — hundreds of
//! flags, thousands of inputs. Incidents become tractable lab cases
//! only when reduced to the smallest set of elements that still
//! reproduces the divergence. The engine is classic delta debugging
//! (Zeller's ddmin) over ANY element type with a caller-supplied
//! reproduction probe:
//!
//! - the probe is the ONLY oracle: an element set "reproduces" iff the
//!   probe says so, and the probe re-runs the real comparison — the
//!   minimizer never infers;
//! - the result is **1-minimal**: removing any single remaining
//!   element loses the divergence (that is ddmin's guarantee, and the
//!   fixture proves it by exhaustive single-removal checks);
//! - the returned case is FINALLY RE-VERIFIED with one more probe —
//!   a [`MinimizedCase`] can never claim a reproduction its own last
//!   probe did not observe;
//! - probes are budgeted: exhausting the budget is a typed outcome
//!   carrying the best case found so far (marked unverified-minimal),
//!   never an infinite shrink loop and never a silent truncation.
//!
//! Two front-ends wrap the engine: invocation shrinking (whitespace
//! tokens of a corpus command — commands with shell quoting refuse
//! with a typed reason rather than being mis-tokenized) and input-
//! manifest bisection (any labeled element list). The emitted lab-case
//! NDJSON is the Epic T handoff format.

use crate::{DivergenceRecord, ExecutionPath, ReplayCommand, compare};

/// Why an invocation cannot be minimized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimizeRefusal {
    /// The command contains shell quoting; whitespace tokenization
    /// would silently change its meaning mid-shrink.
    QuotedCommand,
    /// The full case did not reproduce under the probe at all —
    /// there is nothing to minimize (stale corpus row or flaky
    /// divergence; the caller hears it, typed).
    DoesNotReproduce,
}

/// The minimization outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedCase<T> {
    /// The 1-minimal reproducing element set.
    pub elements: Vec<T>,
    /// Probes spent.
    pub probes_used: u32,
    /// Whether the FINAL verification probe observed the reproduction
    /// on exactly `elements`. False only on budget exhaustion, where
    /// `elements` is the best known reproducing set but 1-minimality
    /// was not established.
    pub verified_minimal: bool,
}

/// Classic ddmin: reduce `elements` to a 1-minimal subset for which
/// `probe` returns true. `probe(&full set)` MUST be true (callers
/// check first). `budget` bounds probe invocations.
pub fn ddmin<T: Clone>(
    elements: &[T],
    probe: &mut dyn FnMut(&[T]) -> bool,
    budget: u32,
) -> MinimizedCase<T> {
    let mut current: Vec<T> = elements.to_vec();
    let mut probes_used: u32 = 0;
    let mut granularity: usize = 2;
    while current.len() >= 2 {
        let chunk = current.len().div_ceil(granularity);
        let mut reduced = false;
        // Try each subset, then each complement.
        let mut start = 0;
        while start < current.len() {
            let end = (start + chunk).min(current.len());
            let complement: Vec<T> = current[..start]
                .iter()
                .chain(&current[end..])
                .cloned()
                .collect();
            if probes_used >= budget {
                return MinimizedCase {
                    elements: current,
                    probes_used,
                    verified_minimal: false,
                };
            }
            probes_used += 1;
            if !complement.is_empty() && probe(&complement) {
                current = complement;
                granularity = 2.max(granularity - 1);
                reduced = true;
                break;
            }
            start = end;
        }
        if !reduced {
            if granularity >= current.len() {
                break;
            }
            granularity = (granularity * 2).min(current.len());
        }
    }
    // Final verification on exactly the returned set.
    let verified = if probes_used < budget {
        probes_used += 1;
        probe(&current)
    } else {
        false
    };
    MinimizedCase {
        elements: current,
        probes_used,
        verified_minimal: verified,
    }
}

/// Shrink a diverging invocation to its minimal reproducing token set.
/// The probe re-runs baseline + candidate on each shrunk command and
/// asks the REAL comparison whether it still diverges.
///
/// # Errors
/// Typed [`MinimizeRefusal`].
pub fn minimize_invocation(
    invocation: &ReplayCommand,
    baseline: &mut dyn ExecutionPath,
    candidate: &mut dyn ExecutionPath,
    budget: u32,
) -> Result<MinimizedCase<String>, MinimizeRefusal> {
    if invocation.command.contains('\'') || invocation.command.contains('"') {
        return Err(MinimizeRefusal::QuotedCommand);
    }
    let tokens: Vec<String> = invocation
        .command
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let mut run = |subset: &[String]| -> bool {
        let shrunk = ReplayCommand {
            command: subset.join(" "),
            ..invocation.clone()
        };
        let base = baseline.execute(&shrunk);
        let cand = candidate.execute(&shrunk);
        compare(&shrunk, &base, &cand).diverged()
    };
    if !run(&tokens) {
        return Err(MinimizeRefusal::DoesNotReproduce);
    }
    // One probe spent on the full-case check above.
    Ok(ddmin(&tokens, &mut run, budget.saturating_sub(1)))
}

/// Bisect an input manifest (any labeled element list) to the minimal
/// subset that still reproduces, via the same engine.
///
/// # Errors
/// [`MinimizeRefusal::DoesNotReproduce`] when the full manifest does
/// not reproduce under the probe.
pub fn minimize_input_manifest<T: Clone>(
    manifest: &[T],
    probe: &mut dyn FnMut(&[T]) -> bool,
    budget: u32,
) -> Result<MinimizedCase<T>, MinimizeRefusal> {
    if !probe(manifest) {
        return Err(MinimizeRefusal::DoesNotReproduce);
    }
    Ok(ddmin(manifest, probe, budget.saturating_sub(1)))
}

/// The Epic T lab-case handoff line: the minimized command, the
/// divergence row it reproduces, and the minimization provenance.
#[must_use]
pub fn lab_case_to_ndjson(
    minimized: &MinimizedCase<String>,
    divergence: &DivergenceRecord,
) -> String {
    serde_json::json!({
        "schema": "rabs.minimized-lab-case",
        "schema_version": 1,
        "command": minimized.elements.join(" "),
        "verified_minimal": minimized.verified_minimal,
        "probes_used": minimized.probes_used,
        "baseline_path": divergence.baseline_path,
        "candidate_path": divergence.candidate_path,
        "outcome_diverged": divergence.outcome_diverged,
        "stdout_diverged": divergence.stdout_diverged,
        "stderr_diverged": divergence.stderr_diverged,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Availability, NormalizedOutcome, PathObservation, StockPath};

    /// The seeded synthetic divergence: a candidate that diverges IFF
    /// the command contains BOTH trigger tokens (a conjunction, so the
    /// minimizer must keep exactly two elements — subtler than a
    /// single-token trigger).
    struct SeededCandidate {
        stock: StockPath,
    }
    impl ExecutionPath for SeededCandidate {
        fn name(&self) -> &str {
            "seeded-candidate"
        }
        fn execute(&mut self, invocation: &ReplayCommand) -> PathObservation {
            let mut observation = self.stock.execute(invocation);
            observation.path_name = self.name().to_owned();
            if invocation.command.contains("--trigger-a")
                && invocation.command.contains("--trigger-b")
            {
                observation.stdout_digest ^= 0xDEAD_BEEF;
            }
            observation
        }
    }

    fn invocation(command: &str) -> ReplayCommand {
        ReplayCommand {
            command: command.to_owned(),
            cwd: "/tmp".to_owned(),
            recorded_outcome: NormalizedOutcome::Exited(0),
            recorded_duration_ms: 1,
        }
    }

    #[test]
    fn b011_seeded_synthetic_divergence_minimizes_to_the_exact_trigger_set() {
        // THE acceptance: a long noisy command whose divergence needs
        // exactly {--trigger-a, --trigger-b}. echo exits 0 whatever
        // the arguments, so every shrunk command still runs — the
        // DIVERGENCE property, not runnability, drives the shrink.
        let noisy = invocation(
            "echo --opt-1 --opt-2 --trigger-a --opt-3 --opt-4 --opt-5 \
             --trigger-b --opt-6 --opt-7 --opt-8 --opt-9 --opt-10",
        );
        let mut baseline = StockPath;
        let mut candidate = SeededCandidate { stock: StockPath };
        let case = minimize_invocation(&noisy, &mut baseline, &mut candidate, 500).unwrap();
        assert!(case.verified_minimal, "final probe must re-verify");
        assert!(case.elements.contains(&"--trigger-a".to_owned()));
        assert!(case.elements.contains(&"--trigger-b".to_owned()));
        // 1-minimality, proven exhaustively: removing ANY single
        // remaining element loses the reproduction.
        let mut probe = |subset: &[String]| {
            let shrunk = ReplayCommand {
                command: subset.join(" "),
                ..noisy.clone()
            };
            let mut b = StockPath;
            let mut c = SeededCandidate { stock: StockPath };
            let base = b.execute(&shrunk);
            let cand = c.execute(&shrunk);
            compare(&shrunk, &base, &cand).diverged()
        };
        for drop_index in 0..case.elements.len() {
            let mut without: Vec<String> = case.elements.clone();
            without.remove(drop_index);
            assert!(
                !probe(&without),
                "dropping {:?} still reproduced — not 1-minimal",
                case.elements[drop_index]
            );
        }
        // The lab-case handoff line carries the minimized command.
        let base = StockPath.execute(&noisy);
        let cand = SeededCandidate { stock: StockPath }.execute(&noisy);
        let row = compare(&noisy, &base, &cand);
        let line = lab_case_to_ndjson(&case, &row);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["schema"], "rabs.minimized-lab-case");
        assert_eq!(parsed["verified_minimal"], true);
        assert!(
            parsed["command"]
                .as_str()
                .unwrap()
                .contains("--trigger-a")
        );
    }

    #[test]
    fn b011_input_manifest_bisection_uses_the_same_engine() {
        // Manifest of 40 labeled inputs; the divergence needs exactly
        // inputs 13 and 29 present.
        let manifest: Vec<u32> = (0..40).collect();
        let mut probes = 0u32;
        let mut probe = |subset: &[u32]| {
            probes += 1;
            subset.contains(&13) && subset.contains(&29)
        };
        let case = minimize_input_manifest(&manifest, &mut probe, 500).unwrap();
        assert!(case.verified_minimal);
        assert_eq!(case.elements, vec![13, 29]);
        assert!(probes > 0);
    }

    #[test]
    fn b011_refusals_are_typed_never_silent() {
        // Quoted commands refuse: whitespace tokenization would change
        // their meaning mid-shrink.
        let quoted = invocation("sh -c 'echo hi'");
        let mut baseline = StockPath;
        let mut candidate = SeededCandidate { stock: StockPath };
        assert_eq!(
            minimize_invocation(&quoted, &mut baseline, &mut candidate, 100),
            Err(MinimizeRefusal::QuotedCommand)
        );
        // A case that does not reproduce at full size refuses — there
        // is nothing to minimize, and the caller hears it.
        let benign = invocation("echo --opt-1 --opt-2");
        assert_eq!(
            minimize_invocation(&benign, &mut baseline, &mut candidate, 100),
            Err(MinimizeRefusal::DoesNotReproduce)
        );
    }

    #[test]
    fn b011_budget_exhaustion_returns_best_known_unverified() {
        // A tight budget cannot finish: the outcome is typed —
        // verified_minimal = false, best-known reproducing set kept,
        // probes bounded by the budget.
        let manifest: Vec<u32> = (0..64).collect();
        let mut probe = |subset: &[u32]| subset.contains(&7) && subset.contains(&55);
        let case = minimize_input_manifest(&manifest, &mut probe, 4).unwrap();
        assert!(!case.verified_minimal);
        assert!(case.probes_used <= 4);
        assert!(case.elements.contains(&7) && case.elements.contains(&55));
    }
}
