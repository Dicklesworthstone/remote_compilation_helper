//! Scenario labels + validated replay selection (bead B006).
//!
//! The quantitative RABS targets are STRATIFIED — "15-agent storm
//! ≥3×", "branch ping-pong ≥3×" — and an unlabeled corpus cannot
//! prove them. Labels here follow a declare-then-validate discipline:
//!
//! - the benchmark orchestrator DECLARES the scenario it constructed
//!   (it knows — it built the storm);
//! - the validator CHECKS the declaration against observable session
//!   signatures where a signature exists: a storm must actually show
//!   the declared interval overlap, a no-op session must actually be
//!   repeated identical successful invocations, a ping-pong must
//!   actually alternate between exactly two invocation identities, a
//!   CI session must actually carry the CI marker on every record;
//! - labels whose defining evidence is NOT in the corpus (clean
//!   checkout state, leaf-vs-root edit shape, IDE origin) validate as
//!   typed [`LabelCheck::Unverifiable`] naming what is missing —
//!   never silently "confirmed";
//! - a declaration the evidence CONTRADICTS is typed
//!   [`LabelCheck::Contradicted`] with the observed figure, so a
//!   mislabeled corpus cannot feed a stratified gate.
//!
//! Replay selection filters by label, and the gates that prove
//! quantitative targets select `Confirmed` sessions only.

use crate::ReplaySkip;

/// The benchmark scenario vocabulary (plan §141's stratification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioLabel {
    /// Full build from a clean state.
    Clean,
    /// Rebuild with nothing changed.
    NoOp,
    /// Edit in a leaf crate.
    LeafEdit,
    /// Edit in a root/widely-depended crate.
    RootEdit,
    /// Alternating checkouts (branch ping-pong).
    BranchSwitch {
        /// Minimum alternations the declaration claims.
        min_alternations: u32,
    },
    /// Many concurrent agents building (the storm scenario).
    AgentStorm {
        /// Peak concurrency the declaration claims.
        min_overlap: u32,
    },
    /// CI-environment session.
    Ci,
    /// IDE-integration session.
    Ide,
}

/// One session record's stratification evidence, parsed from the B002
/// spool line (the spool-level fields the recorder writes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRecord {
    /// Correlation digest of the invocation (identity for
    /// repeat/alternation signatures).
    pub argv_correlation: u64,
    /// Arrival wall-clock, Unix milliseconds.
    pub recorded_at_unix_ms: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the invocation exited 0.
    pub exited_zero: bool,
    /// Whether the CI environment marker was set at record time.
    pub ci_env: bool,
}

/// Parse the stratification fields from one spool line.
///
/// # Errors
/// [`ReplaySkip::MalformedRecord`] naming the missing field.
pub fn parse_session_record(line: &str) -> Result<SessionRecord, ReplaySkip> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ReplaySkip::MalformedRecord {
            detail: e.to_string(),
        })?;
    let field_u64 = |name: &str| {
        value[name]
            .as_u64()
            .ok_or_else(|| ReplaySkip::MalformedRecord {
                detail: format!("{name} missing"),
            })
    };
    Ok(SessionRecord {
        argv_correlation: field_u64("argv_correlation")?,
        recorded_at_unix_ms: field_u64("recorded_at_unix_ms")?,
        duration_ms: field_u64("duration_ms")?,
        exited_zero: value["outcome_kind"] == "exited" && value["outcome_value"] == 0,
        ci_env: value["ci_env"].as_bool().unwrap_or(false),
    })
}

/// The validation verdict for one declared label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelCheck {
    /// The observable signature CONFIRMS the declaration.
    Confirmed,
    /// The evidence contradicts the declaration (the figure observed
    /// is named — a mislabeled corpus cannot feed a stratified gate).
    Contradicted {
        /// What the evidence actually showed.
        why: String,
    },
    /// This label's defining evidence is not in the corpus; the
    /// declaration stands on the orchestrator's authority alone.
    Unverifiable {
        /// What evidence would be needed.
        missing: &'static str,
    },
}

/// Peak interval overlap across records (start, start+duration).
#[must_use]
pub fn peak_overlap(records: &[SessionRecord]) -> u32 {
    let mut events: Vec<(u64, i32)> = Vec::with_capacity(records.len() * 2);
    for r in records {
        events.push((r.recorded_at_unix_ms, 1));
        events.push((
            r.recorded_at_unix_ms.saturating_add(r.duration_ms.max(1)),
            -1,
        ));
    }
    // Ends sort before starts at the same instant (half-open interval).
    events.sort_by_key(|(t, delta)| (*t, *delta));
    let mut current: i32 = 0;
    let mut peak: i32 = 0;
    for (_, delta) in events {
        current += delta;
        peak = peak.max(current);
    }
    u32::try_from(peak.max(0)).unwrap_or(0)
}

/// Count alternations in a period-2 ping-pong (A B A B …): transitions
/// between exactly two identities. Any third identity breaks the
/// signature entirely.
fn ping_pong_alternations(records: &[SessionRecord]) -> Option<u32> {
    let mut identities: Vec<u64> = Vec::new();
    for r in records {
        if !identities.contains(&r.argv_correlation) {
            identities.push(r.argv_correlation);
        }
    }
    if identities.len() != 2 {
        return None;
    }
    let mut alternations = 0;
    for pair in records.windows(2) {
        if pair[0].argv_correlation == pair[1].argv_correlation {
            return None; // A A breaks strict ping-pong.
        }
        alternations += 1;
    }
    Some(alternations)
}

/// Validate one declared label against the session's records.
#[must_use]
pub fn validate_label(label: ScenarioLabel, records: &[SessionRecord]) -> LabelCheck {
    match label {
        ScenarioLabel::AgentStorm { min_overlap } => {
            let observed = peak_overlap(records);
            if observed >= min_overlap {
                LabelCheck::Confirmed
            } else {
                LabelCheck::Contradicted {
                    why: format!("declared overlap >= {min_overlap}, observed {observed}"),
                }
            }
        }
        ScenarioLabel::NoOp => {
            if records.len() < 2 {
                return LabelCheck::Contradicted {
                    why: format!("no-op needs >= 2 records, got {}", records.len()),
                };
            }
            let first = records[0].argv_correlation;
            if let Some(odd) = records.iter().find(|r| r.argv_correlation != first) {
                return LabelCheck::Contradicted {
                    why: format!(
                        "no-op requires identical invocations; {:x} differs from {:x}",
                        odd.argv_correlation, first
                    ),
                };
            }
            if records.iter().any(|r| !r.exited_zero) {
                return LabelCheck::Contradicted {
                    why: "no-op requires every rebuild to succeed".to_owned(),
                };
            }
            LabelCheck::Confirmed
        }
        ScenarioLabel::BranchSwitch { min_alternations } => match ping_pong_alternations(records) {
            Some(observed) if observed >= min_alternations => LabelCheck::Confirmed,
            Some(observed) => LabelCheck::Contradicted {
                why: format!("declared >= {min_alternations} alternations, observed {observed}"),
            },
            None => LabelCheck::Contradicted {
                why: "records do not alternate between exactly two identities".to_owned(),
            },
        },
        ScenarioLabel::Ci => {
            if records.iter().all(|r| r.ci_env) {
                LabelCheck::Confirmed
            } else {
                let missing = records.iter().filter(|r| !r.ci_env).count();
                LabelCheck::Contradicted {
                    why: format!("{missing} record(s) lack the CI environment marker"),
                }
            }
        }
        // The corpus records neither checkout cleanliness nor edit
        // shape nor IDE origin — these declarations stand on the
        // orchestrator's authority, and the verdict SAYS so.
        ScenarioLabel::Clean => LabelCheck::Unverifiable {
            missing: "checkout/target cleanliness is not recorded in the corpus",
        },
        ScenarioLabel::LeafEdit | ScenarioLabel::RootEdit => LabelCheck::Unverifiable {
            missing: "edit shape (leaf vs root) is not recorded in the corpus",
        },
        ScenarioLabel::Ide => LabelCheck::Unverifiable {
            missing: "IDE origin is not recorded in the corpus",
        },
    }
}

/// A labeled session: the declaration, its validation verdict, and the
/// raw corpus lines for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabeledSession {
    /// The declared scenario.
    pub label: ScenarioLabel,
    /// The validation verdict (computed at construction).
    pub check: LabelCheck,
    /// The session's spool lines, replay-ready.
    pub lines: Vec<String>,
}

impl LabeledSession {
    /// Build from a declaration + spool lines; the verdict is computed
    /// HERE so a session cannot carry a stale or hand-written one.
    ///
    /// # Errors
    /// The first malformed line's [`ReplaySkip`].
    pub fn new(label: ScenarioLabel, lines: Vec<String>) -> Result<Self, ReplaySkip> {
        let records: Vec<SessionRecord> = lines
            .iter()
            .map(|l| parse_session_record(l))
            .collect::<Result<_, _>>()?;
        let check = validate_label(label, &records);
        Ok(Self {
            label,
            check,
            lines,
        })
    }
}

/// Replay selection: sessions matching the wanted label kind. Gates
/// proving quantitative targets pass `confirmed_only = true` — an
/// Unverifiable or Contradicted storm never enters a ≥3× proof.
#[must_use]
pub fn select_sessions<'a>(
    sessions: &'a [LabeledSession],
    wanted: &ScenarioLabel,
    confirmed_only: bool,
) -> Vec<&'a LabeledSession> {
    sessions
        .iter()
        .filter(|s| {
            std::mem::discriminant(&s.label) == std::mem::discriminant(wanted)
                && (!confirmed_only || s.check == LabelCheck::Confirmed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(correlation: u64, start: u64, duration: u64) -> SessionRecord {
        SessionRecord {
            argv_correlation: correlation,
            recorded_at_unix_ms: start,
            duration_ms: duration,
            exited_zero: true,
            ci_env: false,
        }
    }

    fn line(correlation: u64, start: u64, duration: u64, ci: bool) -> String {
        serde_json::json!({
            "schema": "rabs.invocation-record",
            "argv_correlation": correlation,
            "recorded_at_unix_ms": start,
            "duration_ms": duration,
            "outcome_kind": "exited",
            "outcome_value": 0,
            "ci_env": ci,
        })
        .to_string()
    }

    #[test]
    fn b006_storm_labels_validate_from_observed_overlap() {
        // 15 overlapping intervals: a declared 15-agent storm confirms;
        // a declared 20-agent storm is CONTRADICTED with the figure.
        let records: Vec<SessionRecord> = (0..15).map(|i| record(i, 1000 + i * 10, 5000)).collect();
        assert_eq!(peak_overlap(&records), 15);
        assert_eq!(
            validate_label(ScenarioLabel::AgentStorm { min_overlap: 15 }, &records),
            LabelCheck::Confirmed
        );
        let LabelCheck::Contradicted { why } =
            validate_label(ScenarioLabel::AgentStorm { min_overlap: 20 }, &records)
        else {
            panic!("overstated storm must be contradicted");
        };
        assert!(why.contains("observed 15"), "{why}");
        // Sequential (non-overlapping) invocations are never a storm.
        let sequential: Vec<SessionRecord> = (0..15).map(|i| record(i, i * 10_000, 5000)).collect();
        assert_eq!(peak_overlap(&sequential), 1);
    }

    #[test]
    fn b006_noop_and_ping_pong_signatures_validate() {
        // No-op: identical successful invocations confirm…
        let noop: Vec<SessionRecord> = (0..3).map(|i| record(7, i * 1000, 100)).collect();
        assert_eq!(
            validate_label(ScenarioLabel::NoOp, &noop),
            LabelCheck::Confirmed
        );
        // …a different command in the middle contradicts.
        let mut mixed = noop.clone();
        mixed[1].argv_correlation = 8;
        assert!(matches!(
            validate_label(ScenarioLabel::NoOp, &mixed),
            LabelCheck::Contradicted { .. }
        ));
        // Ping-pong: A B A B confirms at 3 alternations…
        let pp: Vec<SessionRecord> = [7u64, 8, 7, 8]
            .iter()
            .enumerate()
            .map(|(i, c)| record(*c, i as u64 * 1000, 100))
            .collect();
        assert_eq!(
            validate_label(
                ScenarioLabel::BranchSwitch {
                    min_alternations: 3
                },
                &pp
            ),
            LabelCheck::Confirmed
        );
        // …A A B B does not alternate strictly.
        let lumpy: Vec<SessionRecord> = [7u64, 7, 8, 8]
            .iter()
            .enumerate()
            .map(|(i, c)| record(*c, i as u64 * 1000, 100))
            .collect();
        assert!(matches!(
            validate_label(
                ScenarioLabel::BranchSwitch {
                    min_alternations: 1
                },
                &lumpy
            ),
            LabelCheck::Contradicted { .. }
        ));
    }

    #[test]
    fn b006_unverifiable_labels_say_so_instead_of_confirming() {
        let records = [record(1, 0, 10)];
        for label in [
            ScenarioLabel::Clean,
            ScenarioLabel::LeafEdit,
            ScenarioLabel::RootEdit,
            ScenarioLabel::Ide,
        ] {
            assert!(
                matches!(
                    validate_label(label, &records),
                    LabelCheck::Unverifiable { .. }
                ),
                "{label:?} has no corpus signature and must say so"
            );
        }
        // CI validates from the recorded marker.
        let ci_ok = [SessionRecord {
            ci_env: true,
            ..record(1, 0, 10)
        }];
        assert_eq!(
            validate_label(ScenarioLabel::Ci, &ci_ok),
            LabelCheck::Confirmed
        );
        assert!(matches!(
            validate_label(ScenarioLabel::Ci, &records),
            LabelCheck::Contradicted { .. }
        ));
    }

    #[test]
    fn b006_replay_selection_filters_by_label_and_confirmation() {
        let storm_lines: Vec<String> = (0..3)
            .map(|i| line(i, 1000 + i * 10, 5000, false))
            .collect();
        let fake_storm_lines: Vec<String> =
            (0..3).map(|i| line(i, i * 100_000, 10, false)).collect();
        let noop_lines: Vec<String> = (0..2).map(|i| line(9, i * 1000, 50, false)).collect();
        let sessions = vec![
            LabeledSession::new(ScenarioLabel::AgentStorm { min_overlap: 3 }, storm_lines).unwrap(),
            LabeledSession::new(
                ScenarioLabel::AgentStorm { min_overlap: 3 },
                fake_storm_lines,
            )
            .unwrap(),
            LabeledSession::new(ScenarioLabel::NoOp, noop_lines).unwrap(),
        ];
        // Label filter alone: both storm declarations match.
        let storms = select_sessions(
            &sessions,
            &ScenarioLabel::AgentStorm { min_overlap: 3 },
            false,
        );
        assert_eq!(storms.len(), 2);
        // Confirmed-only (what a >=3x gate uses): the fake storm —
        // sequential invocations mislabeled as a storm — is excluded.
        let confirmed = select_sessions(
            &sessions,
            &ScenarioLabel::AgentStorm { min_overlap: 3 },
            true,
        );
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].check, LabelCheck::Confirmed);
        // And the label vocabulary covers the full benchmark list.
        let _every: [ScenarioLabel; 8] = [
            ScenarioLabel::Clean,
            ScenarioLabel::NoOp,
            ScenarioLabel::LeafEdit,
            ScenarioLabel::RootEdit,
            ScenarioLabel::BranchSwitch {
                min_alternations: 1,
            },
            ScenarioLabel::AgentStorm { min_overlap: 2 },
            ScenarioLabel::Ci,
            ScenarioLabel::Ide,
        ];
    }
}
