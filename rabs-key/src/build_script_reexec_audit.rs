//! Deterministic re-execution audits + shared-cache denylist for
//! build-script runs (bead N007; plan Epic N/m11; consumes the
//! byte-exact captures of [`crate::build_script_directives`]).
//!
//! A cached build-script run may be SERVED only if re-running the
//! script would produce the same world. Trusting that claim is how a
//! nondeterministic script (timestamps, directory listings, network
//! pokes) poisons every downstream action silently. The N007 law:
//!
//! - **Sampled re-execution audit**: periodically re-run a cached
//!   build script under identical declared inputs and compare the new
//!   capture against the cached one — BYTE-EXACT stdout (the capture's
//!   reconstruct anchor), SEMANTIC directive sets, and exit code. All
//!   three lenses report independently so operators can see WHAT kind
//!   of nondeterminism they have;
//! - **Divergence quarantines**: any divergent script enters the
//!   shared-cache denylist WITH ITS EVIDENCE RETAINED verbatim. A
//!   quarantined script is never served from cache again — its runs
//!   execute live — until a human re-admits it by clearing the entry
//!   deliberately. There is no automatic forgiveness: a script that
//!   lied once gets the benefit of no doubt;
//! - **The denylist is content-addressed**: keyed by the SCRIPT's
//!   identity digest (not its path — moving a bad script does not
//!   launder it), deterministic in serialization, order-insensitive.
//!
//! Pure policy over captured facts; execution lives elsewhere.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync; record digests via the
//! reviewed sha2 path ([`crate::typed_digest::compute`]).

use crate::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;

/// Digest domain for denylist records.
pub const DOMAIN_BUILD_SCRIPT_DENYLIST: &str = "rabs.build-script-denylist.v1";

/// One observed difference between cached and re-executed captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// Reconstructed stdout bytes differ from the cached capture.
    OutputByteDrift {
        /// Cached reconstruct length (bytes).
        cached_len: usize,
        /// Re-run reconstruct length (bytes).
        rerun_len: usize,
        /// Byte offset of the FIRST differing byte, when lengths overlap.
        first_diff_offset: Option<usize>,
    },
    /// Semantic directive sets differ (a rerun-if-changed appeared,
    /// disappeared, or changed value).
    DirectiveDrift {
        /// The directive as rendered by the cached capture.
        cached_directive: String,
        /// The same-index semantic directive from the re-run.
        rerun_directive: String,
    },
    /// Exit codes differ.
    ExitCodeDrift {
        /// Cached run's exit code.
        cached_exit: i32,
        /// Re-run's exit code.
        rerun_exit: i32,
    },
}

impl Divergence {
    /// Stable wire tag for metrics/aggregation.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::OutputByteDrift { .. } => "output-byte-drift",
            Self::DirectiveDrift { .. } => "directive-drift",
            Self::ExitCodeDrift { .. } => "exit-code-drift",
        }
    }
}

/// The verdict of one sampled re-execution audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    /// Cached and re-executed captures agree on every lens.
    Deterministic,
    /// At least one lens disagrees; all divergences are listed.
    Diverged { divergences: Vec<Divergence> },
}

impl AuditVerdict {
    /// Whether this verdict permits continued cache serving.
    #[must_use]
    pub const fn serving_allowed(&self) -> bool {
        matches!(self, Self::Deterministic)
    }
}

/// Judge one sampled re-execution: compare cached vs re-run captures
/// across all lenses. Inputs are OBSERVED facts (captures + exit
/// codes); the caller owns actually running the script twice.
///
/// Note on lens independence: `DirectiveDrift` entries are reported
/// only while the byte-level comparison ALSO drifts or alongside it —
/// byte equality implies directive equality, but reporting both makes
/// the operator's diagnosis direct rather than inferred.
#[must_use]
pub fn judge(
    cached: &crate::build_script_directives::BuildScriptCapture,
    rerun: &crate::build_script_directives::BuildScriptCapture,
    cached_exit: i32,
    rerun_exit: i32,
) -> AuditVerdict {
    let mut divergences = Vec::new();

    // Lens 1: byte-exact stdout.
    let cached_bytes = cached.reconstruct();
    let rerun_bytes = rerun.reconstruct();
    if cached_bytes != rerun_bytes {
        let first_diff = cached_bytes
            .bytes()
            .zip(rerun_bytes.bytes())
            .position(|(a, b)| a != b);
        divergences.push(Divergence::OutputByteDrift {
            cached_len: cached_bytes.len(),
            rerun_len: rerun_bytes.len(),
            first_diff_offset: first_diff,
        });
    }

    // Lens 2: semantic directives, positionally paired.
    let cached_sem: Vec<String> = cached
        .semantic_directives()
        .map(|d| format!("{d:?}"))
        .collect();
    let rerun_sem: Vec<String> = rerun
        .semantic_directives()
        .map(|d| format!("{d:?}"))
        .collect();
    for (c, r) in cached_sem.iter().zip(rerun_sem.iter()) {
        if c != r {
            divergences.push(Divergence::DirectiveDrift {
                cached_directive: c.clone(),
                rerun_directive: r.clone(),
            });
        }
    }
    if cached_sem.len() != rerun_sem.len() {
        divergences.push(Divergence::DirectiveDrift {
            cached_directive: format!("<count {}>", cached_sem.len()),
            rerun_directive: format!("<count {}>", rerun_sem.len()),
        });
    }

    // Lens 3: exit code.
    if cached_exit != rerun_exit {
        divergences.push(Divergence::ExitCodeDrift {
            cached_exit,
            rerun_exit,
        });
    }

    if divergences.is_empty() {
        AuditVerdict::Deterministic
    } else {
        AuditVerdict::Diverged { divergences }
    }
}

/// One quarantined script: identity plus retained evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyEntry {
    /// Content-identity digest of the divergent build script. Path-
    /// addressed entries would let a move launder the denial; content
    /// addressing cannot.
    pub script_digest: TypedDigest,
    /// The retained divergence evidence, verbatim, append-ordered.
    pub evidence: Vec<Divergence>,
}

/// The shared-cache denylist. Deterministic serialization;
/// order-insensitive membership.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Denylist {
    entries: Vec<DenyEntry>,
}

impl Denylist {
    /// Empty denylist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Quarantine a divergent script with its evidence. Returns `false`
    /// when already listed (existing entry untouched — first evidence
    /// stands, later audits append nothing automatically).
    pub fn quarantine(&mut self, script_digest: TypedDigest, evidence: Vec<Divergence>) -> bool {
        if self.is_quarantined(&script_digest) {
            return false;
        }
        self.entries.push(DenyEntry {
            script_digest,
            evidence,
        });
        self.entries.sort_by(|a, b| {
            (a.script_digest.domain, a.script_digest.bytes.as_slice())
                .cmp(&(b.script_digest.domain, b.script_digest.bytes.as_slice()))
        });
        true
    }

    /// Whether serving is denied for this script identity.
    #[must_use]
    pub fn is_quarantined(&self, script_digest: &TypedDigest) -> bool {
        self.entries
            .iter()
            .any(|e| e.script_digest == *script_digest)
    }

    /// Retained evidence for a quarantined script, if any.
    #[must_use]
    pub fn evidence_for(&self, script_digest: &TypedDigest) -> Option<&[Divergence]> {
        self.entries
            .iter()
            .find(|e| e.script_digest == *script_digest)
            .map(|e| e.evidence.as_slice())
    }

    /// Listed scripts count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the denylist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Deterministic record digest over (identity, evidence) per entry
    /// in sorted order — two fleets comparing denylists can diff by
    /// digest alone.
    #[must_use]
    pub fn digest(&self) -> TypedDigest {
        let mut framed = Vec::new();
        framed.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for e in &self.entries {
            framed.extend_from_slice(e.script_digest.domain.as_bytes());
            framed.extend_from_slice(&e.script_digest.bytes);
            framed.extend_from_slice(&(e.evidence.len() as u64).to_be_bytes());
            for d in &e.evidence {
                framed.extend_from_slice(d.tag().as_bytes());
                match d {
                    Divergence::OutputByteDrift {
                        cached_len,
                        rerun_len,
                        first_diff_offset,
                    } => {
                        framed.extend_from_slice(&(*cached_len as u64).to_be_bytes());
                        framed.extend_from_slice(&(*rerun_len as u64).to_be_bytes());
                        framed.extend_from_slice(
                            &(first_diff_offset.map_or(u64::MAX, |v| v as u64)).to_be_bytes(),
                        );
                    }
                    Divergence::DirectiveDrift {
                        cached_directive,
                        rerun_directive,
                    } => {
                        framed.extend_from_slice(cached_directive.as_bytes());
                        framed.push(0);
                        framed.extend_from_slice(rerun_directive.as_bytes());
                        framed.push(0);
                    }
                    Divergence::ExitCodeDrift {
                        cached_exit,
                        rerun_exit,
                    } => {
                        framed.extend_from_slice(&cached_exit.to_be_bytes());
                        framed.extend_from_slice(&rerun_exit.to_be_bytes());
                    }
                }
            }
        }
        compute(DOMAIN_BUILD_SCRIPT_DENYLIST, &framed)
    }
}

// ---------------------------------------------------------------------
// Tests — N007 acceptance: audit wiring; divergence quarantines.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_script_directives::capture_stdout;

    fn id(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: DOMAIN_BUILD_SCRIPT_DENYLIST,
            bytes: [tag; 32],
        }
    }

    #[test]
    fn matching_reexec_is_deterministic_and_serving_continues() {
        let out = "cargo:rerun-if-changed=build/deps.txt\ncargo:rustc-link-lib=static=foo\n";
        let cached = capture_stdout(out);
        let rerun = capture_stdout(out);
        let v = judge(&cached, &rerun, 0, 0);
        assert_eq!(v, AuditVerdict::Deterministic);
        assert!(v.serving_allowed());

        let dl = Denylist::new();
        assert!(!dl.is_quarantined(&id(1)));
        assert!(matches!(
            judge(&cached, &rerun, 0, 0),
            AuditVerdict::Deterministic
        ));
    }

    #[test]
    fn divergence_reports_all_lenses() {
        let cached = capture_stdout("cargo:rerun-if-changed=a.txt\n");
        let rerun = capture_stdout("cargo:rerun-if-changed=b.txt\nextra noise\n");
        let v = judge(&cached, &rerun, 0, 0);
        match v {
            AuditVerdict::Diverged { divergences } => {
                let tags: Vec<&str> = divergences.iter().map(Divergence::tag).collect();
                assert!(tags.contains(&"output-byte-drift"), "{tags:?}");
                assert!(tags.contains(&"directive-drift"), "{tags:?}");
                assert_eq!(tags.len(), 2);
            }
            other => panic!("expected divergence, got {other:?}"),
        }
        // Exit-code lens fires independently.
        let same = capture_stdout("ok\n");
        match judge(&same, &same, 0, 1) {
            AuditVerdict::Diverged { divergences } => {
                assert_eq!(divergences.len(), 1);
                assert_eq!(divergences[0].tag(), "exit-code-drift");
            }
            other => panic!("expected exit-code drift, got {other:?}"),
        }
    }

    #[test]
    fn divergence_quarantines_with_evidence_retained() {
        let cached = capture_stdout("cargo:rustc-link-lib=static=foo\n");
        let rerun = capture_stdout("cargo:rustc-link-lib=static=bar\n");
        let verdict = judge(&cached, &rerun, 0, 0);
        let script = id(7);

        let mut dl = Denylist::new();
        // Wiring: a divergent audit quarantines and DENIES serving.
        let evidence = match &verdict {
            AuditVerdict::Diverged { divergences } => divergences.clone(),
            AuditVerdict::Deterministic => vec![],
        };
        assert!(!evidence.is_empty());
        assert!(dl.quarantine(script.clone(), evidence.clone()));
        assert!(dl.is_quarantined(&script));
        assert!(!verdict.serving_allowed());
        // Evidence RETAINED verbatim for operator review.
        assert_eq!(dl.evidence_for(&script), Some(evidence.as_slice()));

        // Second quarantine attempt is idempotent: first evidence stands.
        assert!(!dl.quarantine(script.clone(), vec![]));
        assert_eq!(dl.evidence_for(&script), Some(evidence.as_slice()));
    }

    #[test]
    fn denylist_is_content_addressed_and_order_insensitive() {
        // Moving the bad script to a new path does NOT launder it: the
        // key is the content digest, which travels with the file.
        let mut dl = Denylist::new();
        dl.quarantine(
            id(9),
            vec![Divergence::ExitCodeDrift {
                cached_exit: 0,
                rerun_exit: 101,
            }],
        );
        assert!(dl.is_quarantined(&id(9)));

        // Order-insensitive construction → same digest.
        let build = |order: &[u8]| {
            let mut d = Denylist::new();
            for tag in order {
                d.quarantine(
                    id(*tag),
                    vec![Divergence::ExitCodeDrift {
                        cached_exit: 0,
                        rerun_exit: i32::from(*tag),
                    }],
                );
            }
            d
        };
        let x = build(&[1, 2, 3]);
        let y = build(&[3, 1, 2]);
        assert_eq!(x.digest(), y.digest());
        assert_eq!(x.len(), 3);

        // Different evidence for the same identity moves the digest.
        let mut z = build(&[1, 2]);
        z.quarantine(
            id(3),
            vec![Divergence::ExitCodeDrift {
                cached_exit: 0,
                rerun_exit: 99,
            }],
        );
        assert_eq!(z.len(), 3);
        assert_ne!(x.digest(), z.digest());
    }

    #[test]
    fn unquarantined_scripts_keep_serving() {
        let dl = Denylist::new();
        assert!(dl.is_empty());
        assert!(!dl.is_quarantined(&id(42)));
        // And the audit verdict type agrees: only Deterministic serves.
        let good = capture_stdout("ok\n");
        assert!(judge(&good, &good, 0, 0).serving_allowed());
    }
}
