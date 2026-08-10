//! Mtime choreography for served hits (bead D010; risk R6).
//!
//! Cargo's freshness story is mtime arithmetic, so a served hit must
//! land in the subscriber's target tree with mtimes Cargo reads as
//! "already built": outputs at or above every relevant input (the D009
//! floor), source mtimes deterministic (the D009 epoch), and the whole
//! materialization visible ATOMICALLY — a partially renamed target
//! tree is a rebuild storm waiting for the next `cargo build`.
//!
//! The honest edge of the policy is skew: a source whose mtime lies in
//! the FUTURE cannot be choreographed coherently — an output stamped
//! "newer" than it would be a lie that unravels on the next clock tick,
//! and guessing produces exactly the intermittent storms R6 names. Skew
//! therefore forces validated checksum freshness (where the toolchain
//! lane supports it, D015) or a serving bypass — never a guess.

/// Result of assessing input mtimes against the current clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtimeCoherence {
    /// All inputs are in the past: outputs stamped at `output_floor_ns`
    /// satisfy Cargo's newer-than-inputs rule durably.
    Coherent {
        /// The D009 floor: newest input mtime.
        output_floor_ns: u128,
    },
    /// Inputs claim mtimes beyond the current clock (+tolerance): no
    /// coherent output stamp exists.
    SkewedFuture {
        /// The offending (path, mtime_ns) pairs.
        skewed: Vec<(String, u128)>,
    },
}

/// Clock tolerance for FAT-style granularity and small NTP drift (2s).
pub const SKEW_TOLERANCE_NS: u128 = 2_000_000_000;

/// Assess whether the input mtime set can be choreographed coherently.
#[must_use]
pub fn assess_mtime_coherence(now_ns: u128, inputs: &[(String, u128)]) -> MtimeCoherence {
    let horizon = now_ns.saturating_add(SKEW_TOLERANCE_NS);
    let skewed: Vec<(String, u128)> = inputs
        .iter()
        .filter(|(_, mtime)| *mtime > horizon)
        .cloned()
        .collect();
    if skewed.is_empty() {
        MtimeCoherence::Coherent {
            output_floor_ns: inputs.iter().map(|(_, m)| *m).max().unwrap_or(0),
        }
    } else {
        MtimeCoherence::SkewedFuture { skewed }
    }
}

/// How (whether) to serve a hit given coherence and lane capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServingDecision {
    /// Serve with choreographed mtimes (the normal lane).
    ServeWithMtimes {
        /// Output stamp floor.
        output_floor_ns: u128,
    },
    /// Serve under VALIDATED checksum freshness (the D015 opt-in lane);
    /// mtimes are not trusted for these inputs.
    ServeWithChecksumFreshness,
    /// Bypass serving entirely: no coherent story exists — the build
    /// runs for real rather than RABS guessing.
    Bypass {
        /// The skewed inputs that forced the bypass.
        skewed: Vec<(String, u128)>,
    },
}

/// The D010 decision rule: coherent ⇒ mtimes; skewed ⇒ checksum lane
/// only if VALIDATED support exists, else bypass. Never a guess.
#[must_use]
pub fn serving_decision(
    coherence: MtimeCoherence,
    validated_checksum_freshness: bool,
) -> ServingDecision {
    match coherence {
        MtimeCoherence::Coherent { output_floor_ns } => {
            ServingDecision::ServeWithMtimes { output_floor_ns }
        }
        MtimeCoherence::SkewedFuture { skewed } => {
            if validated_checksum_freshness {
                ServingDecision::ServeWithChecksumFreshness
            } else {
                ServingDecision::Bypass { skewed }
            }
        }
    }
}

/// Materialize a fully-staged tree into place ATOMICALLY: the final
/// path either does not exist or is the complete tree — never a partial
/// one — because the only mutation of `final_path` is a single
/// `rename(2)`. The staging tree must be complete before this is
/// called; a failed staging simply never renames.
pub fn commit_staged_tree(
    staging: &std::path::Path,
    final_path: &std::path::Path,
) -> std::io::Result<()> {
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(staging, final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u128 = 1_700_000_000_000_000_000;

    #[test]
    fn past_inputs_are_coherent_with_the_newest_as_floor() {
        let inputs = vec![
            ("src/main.rs".to_string(), NOW - 5_000_000_000),
            ("Cargo.lock".to_string(), NOW - 1_000_000_000),
        ];
        assert_eq!(
            assess_mtime_coherence(NOW, &inputs),
            MtimeCoherence::Coherent {
                output_floor_ns: NOW - 1_000_000_000
            }
        );
    }

    #[test]
    fn future_mtimes_beyond_tolerance_are_skew_within_it_are_not() {
        // 1s ahead: inside tolerance, coherent.
        let near = vec![("a.rs".to_string(), NOW + 1_000_000_000)];
        assert!(matches!(
            assess_mtime_coherence(NOW, &near),
            MtimeCoherence::Coherent { .. }
        ));
        // 1 hour ahead: skewed, and the offender is named.
        let far = vec![
            ("a.rs".to_string(), NOW),
            ("clock-broken.rs".to_string(), NOW + 3_600_000_000_000),
        ];
        let MtimeCoherence::SkewedFuture { skewed } = assess_mtime_coherence(NOW, &far) else {
            panic!("expected skew");
        };
        assert_eq!(skewed.len(), 1);
        assert_eq!(skewed[0].0, "clock-broken.rs");
    }

    #[test]
    fn skew_forces_checksum_lane_or_bypass_never_a_guess() {
        let skewed = MtimeCoherence::SkewedFuture {
            skewed: vec![("x.rs".to_string(), NOW + 9_000_000_000_000)],
        };
        // Validated checksum lane available: serve through it.
        assert_eq!(
            serving_decision(skewed.clone(), true),
            ServingDecision::ServeWithChecksumFreshness
        );
        // THE acceptance's bypass arm: no validated lane ⇒ bypass,
        // carrying the offenders for `rch why`.
        let ServingDecision::Bypass { skewed: offenders } = serving_decision(skewed, false) else {
            panic!("expected bypass");
        };
        assert_eq!(offenders[0].0, "x.rs");
        // Coherent inputs always serve with mtimes.
        assert_eq!(
            serving_decision(MtimeCoherence::Coherent { output_floor_ns: 7 }, false),
            ServingDecision::ServeWithMtimes { output_floor_ns: 7 }
        );
    }

    #[test]
    fn skewed_mtime_fixture_on_a_real_file_bypasses() {
        // A real file stamped one year in the future — the observed
        // mtime feeds the same decision path and must bypass.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.rs");
        std::fs::write(&path, "fn f() {}\n").unwrap();
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(31_536_000);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mtime_ns = std::fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let coherence = assess_mtime_coherence(now_ns, &[("future.rs".to_string(), mtime_ns)]);
        assert!(matches!(
            serving_decision(coherence, false),
            ServingDecision::Bypass { .. }
        ));
    }

    #[test]
    fn staged_tree_commits_atomically_and_incomplete_staging_never_lands() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("staging");
        let final_path = root.path().join("target/debug");
        std::fs::create_dir_all(staging.join("deps")).unwrap();
        std::fs::write(staging.join("deps/libfx.rmeta"), b"meta").unwrap();

        // Failure BEFORE commit: the final path simply does not exist —
        // there is no partially-renamed state to observe.
        assert!(!final_path.exists());

        commit_staged_tree(&staging, &final_path).unwrap();
        assert!(final_path.join("deps/libfx.rmeta").exists());
        assert!(!staging.exists(), "the staging tree moved, not copied");
    }
}
