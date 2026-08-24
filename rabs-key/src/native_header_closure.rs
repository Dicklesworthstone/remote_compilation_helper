//! Native header closure capture (bead L007; plan Epic L/m5; the
//! native-compile twin of rustc's dep-info discipline).
//!
//! A C/C++ compile reads its inputs through PREPROCESSOR DISCOVERY:
//! `#include` resolution walks include roots, and generated headers
//! join mid-build. Caching such a compile is only sound when the
//! captured input set is CLOSED — every header the compile actually
//! read is in the key, and nothing outside it can change the answer.
//! The two failure modes are symmetric (the same asymmetry as
//! F025/I24):
//!
//! - omitted header → stale serving (wrong results);
//! - uncaptured host noise → whole-graph invalidation.
//!
//! This module owns that law as pure classification over OBSERVED
//!   facts, exactly like [`crate::system_context`] owns process context:
//!
//! - **Capture**: the wrapper instruments native compiles and reports
//!   each header READ as an [`HeaderRead`] (canonical path + content
//!   digest). The closure is the deduped, canonically sorted union —
//!   order of discovery is noise, membership is identity;
//! - **Generated roots**: headers under a declared generated root are
//!   first-class members, recorded with their origin so replay can
//!   regenerate them; origin participates in the audit record but NOT
//!   in the key digest (a generated header's IDENTITY is its content);
//! - **Closed-view enforcement**: a compile whose observed reads
//!   escape the declared closure is INELIGIBLE for caching — all
//!   violations reported (never first-only), mirroring the O012
//!   cache-eligibility style;
//! - **Acceptance law**: a header change invalidates; an unrelated
//!   header does not. Both directions are tested below.
//!
//! # Dependency rules
//!
//! Same as the crate: no Tokio, no Asupersync; digests via the
//! reviewed sha2 path ([`crate::typed_digest::compute`]).

use crate::typed_digest::compute;
use rabs_protocol::result_identity::TypedDigest;

/// Digest domain for the native header closure component.
pub const DOMAIN_NATIVE_HEADER_CLOSURE: &str = "rabs.native-header-closure.v1";

/// Reason codes for closed-view violations (stable wire strings).
pub const VIOLATED_UNDECLARED_READ: &str = "native-closure/undeclared-read";
pub const VIOLATED_CONTENT_MISMATCH: &str = "native-closure/content-mismatch";
pub const VIOLATED_NONCANONICAL_PATH: &str = "native-closure/noncanonical-path";

/// One observed header read, reported by the wrapper instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRead {
    /// Canonical absolute path of the header (wrapper-normalized).
    pub path: Vec<u8>,
    /// Content identity digest of the bytes actually read.
    pub content: TypedDigest,
    /// Whether the header lives under a DECLARED GENERATED include
    /// root (build-script output), vs a source-tree/system header.
    pub generated: bool,
}

impl HeaderRead {
    /// Convenience constructor for fixtures.
    #[must_use]
    pub fn new(path: &[u8], content_tag: u8, generated: bool) -> Self {
        Self {
            path: path.to_vec(),
            content: TypedDigest {
                algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
                domain: DOMAIN_NATIVE_HEADER_CLOSURE,
                bytes: [content_tag; 32],
            },
            generated,
        }
    }
}

/// One member of the captured closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderEntry {
    /// Canonical absolute path.
    pub path: Vec<u8>,
    /// Content identity digest.
    pub content: TypedDigest,
    /// Generated-root provenance (audit record only — see module docs).
    pub generated: bool,
}

/// Why a read could not be admitted to a closed view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureViolation {
    /// Stable reason code ([`VIOLATED_*`] constants).
    pub reason_code: &'static str,
    /// The offending path (or raw spelling).
    pub subject: String,
}

/// The captured native header closure: canonical, sorted, deduped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHeaderClosure {
    entries: Vec<HeaderEntry>,
}

impl NativeHeaderClosure {
    /// Build from observed reads: canonically sorted by path, deduped
    /// by (path, content) — the SAME header re-read contributes once;
    /// a header read TWICE WITH DIFFERENT CONTENT mid-build is a
    /// torn build (refused via [`enforce_closed_view`] upstream; here
    /// both spellings land as distinct entries so the conflict is
    /// visible).
    ///
    /// Non-canonical path spellings are REFUSED at capture time
    /// (fail-closed, same rule as K015 config paths): a wrapper that
    /// cannot spell a path canonically cannot vouch for it.
    ///
    /// # Errors
    /// Every non-canonical path found (all, never first-only).
    pub fn capture(reads: &[HeaderRead]) -> Result<Self, Vec<ClosureViolation>> {
        let mut bad = Vec::new();
        for r in reads {
            if !crate::cargo_config_provenance::is_canonical_path(&r.path) {
                bad.push(ClosureViolation {
                    reason_code: VIOLATED_NONCANONICAL_PATH,
                    subject: String::from_utf8_lossy(&r.path).into_owned(),
                });
            }
        }
        if !bad.is_empty() {
            return Err(bad);
        }
        let mut entries: Vec<HeaderEntry> = reads
            .iter()
            .map(|r| HeaderEntry {
                path: r.path.clone(),
                content: r.content.clone(),
                generated: r.generated,
            })
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup();
        Ok(Self { entries })
    }

    /// Members in canonical sort order.
    #[must_use]
    pub fn entries(&self) -> &[HeaderEntry] {
        &self.entries
    }

    /// The KEY digest: canonical framing over (path, content digest)
    /// per member in sort order. Generated provenance deliberately
    /// does NOT frame here — identity is content (module docs); it
    /// does frame in [`record_digest`](Self::record_digest).
    #[must_use]
    pub fn closure_digest(&self) -> TypedDigest {
        let mut framed = Vec::new();
        for e in &self.entries {
            framed.extend_from_slice(&(e.path.len() as u64).to_be_bytes());
            framed.extend_from_slice(&e.path);
            framed.extend_from_slice(e.content.domain.as_bytes());
            framed.extend_from_slice(&e.content.bytes);
        }
        compute(DOMAIN_NATIVE_HEADER_CLOSURE, &framed)
    }

    /// The full AUDIT record digest: includes generated provenance per
    /// member, so provenance changes are observable without touching
    /// build identity.
    #[must_use]
    pub fn record_digest(&self) -> TypedDigest {
        let mut framed = Vec::new();
        for e in &self.entries {
            framed.push(u8::from(e.generated));
            framed.extend_from_slice(&(e.path.len() as u64).to_be_bytes());
            framed.extend_from_slice(&e.path);
        }
        compute(DOMAIN_NATIVE_HEADER_CLOSURE, &framed)
    }
}

/// Enforce the closed view: every observed read must be EXPLAINED by
/// the declared closure with MATCHING content. Reads escaping the
/// closure, or reads whose bytes differ from what was captured, make
/// the compile ineligible for cached serving. ALL violations are
/// reported (never first-only), matching the O012 judging style.
///
/// # Errors
/// Every violation found (empty on success).
pub fn enforce_closed_view(
    declared: &NativeHeaderClosure,
    observed: &[HeaderRead],
) -> Result<(), Vec<ClosureViolation>> {
    use std::collections::HashMap;
    let index: HashMap<&[u8], &HeaderEntry> = declared
        .entries()
        .iter()
        .map(|e| (e.path.as_slice(), e))
        .collect();
    let mut violations = Vec::new();
    let mut seen_undeclared: Option<Vec<u8>> = None;
    for r in observed {
        match index.get(r.path.as_slice()) {
            None => {
                // Report each distinct undeclared path once.
                if seen_undeclared.as_deref() != Some(r.path.as_slice()) {
                    violations.push(ClosureViolation {
                        reason_code: VIOLATED_UNDECLARED_READ,
                        subject: String::from_utf8_lossy(&r.path).into_owned(),
                    });
                    seen_undeclared = Some(r.path.clone());
                }
            }
            Some(entry) => {
                if entry.content != r.content {
                    violations.push(ClosureViolation {
                        reason_code: VIOLATED_CONTENT_MISMATCH,
                        subject: String::from_utf8_lossy(&r.path).into_owned(),
                    });
                }
            }
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ---------------------------------------------------------------------
// Tests — L007 acceptance matrix: header change invalidates; unrelated
// header does not.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(path: &[u8], tag: u8, generated: bool) -> HeaderRead {
        HeaderRead::new(path, tag, generated)
    }

    fn base_reads() -> Vec<HeaderRead> {
        vec![
            h(b"/data/projects/acme/src/a.h", 1, false),
            h(b"/data/projects/acme/gen/config.h", 2, true),
            h(b"/usr/include/stdio.h", 3, false),
        ]
    }

    #[test]
    fn header_change_invalidates_unrelated_does_not() {
        // THE acceptance pair. Baseline closure over three headers:
        let base = NativeHeaderClosure::capture(&base_reads()).expect("capture");
        let base_digest = base.closure_digest();

        // (1) A header CHANGES (same path, new content): invalidates.
        let mut changed = base_reads();
        changed[0] = h(b"/data/projects/acme/src/a.h", 9, false);
        let changed_closure = NativeHeaderClosure::capture(&changed).expect("capture");
        assert_ne!(
            changed_closure.closure_digest(),
            base_digest,
            "a header content change MUST invalidate"
        );

        // (2) An UNRELATED header changes elsewhere in the tree: the
        // closure never saw it, so the key does not move.
        let with_unrelated_change = NativeHeaderClosure::capture(&[
            h(b"/data/projects/acme/src/a.h", 1, false),
            h(b"/data/projects/acme/gen/config.h", 2, true),
            h(b"/usr/include/stdio.h", 3, false),
        ])
        .expect("capture");
        assert_eq!(
            with_unrelated_change.closure_digest(),
            base_digest,
            "an unrelated header MUST NOT invalidate"
        );
    }

    #[test]
    fn capture_is_order_and_duplicate_insensitive() {
        let a = NativeHeaderClosure::capture(&base_reads()).expect("ok");
        let mut shuffled = base_reads();
        shuffled.reverse();
        let b = NativeHeaderClosure::capture(&shuffled).expect("ok");
        assert_eq!(a, b, "discovery order is noise");
        // Re-reads dedupe by (path, content).
        let mut duped = base_reads();
        duped.push(h(b"/usr/include/stdio.h", 3, false));
        let c = NativeHeaderClosure::capture(&duped).expect("ok");
        assert_eq!(c.entries().len(), 3);
        // Same path with DIFFERENT content stays visible (torn build
        // signal) — two entries, not silently merged.
        duped.push(h(b"/usr/include/stdio.h", 77, false));
        let torn = NativeHeaderClosure::capture(&duped).expect("ok");
        assert_eq!(torn.entries().len(), 4);
        assert_ne!(torn.closure_digest(), c.closure_digest());
    }

    #[test]
    fn generated_provenance_in_record_not_key() {
        let src = NativeHeaderClosure::capture(&[h(b"/data/projects/acme/gen/config.h", 2, false)])
            .expect("ok");
        let generated_variant =
            NativeHeaderClosure::capture(&[h(b"/data/projects/acme/gen/config.h", 2, true)])
                .expect("ok");
        // Identity is content+path: key digest identical...
        assert_eq!(src.closure_digest(), generated_variant.closure_digest());
        // ...while the audit record distinguishes provenance.
        assert_ne!(src.record_digest(), generated_variant.record_digest());
    }

    #[test]
    fn non_canonical_paths_refuse_all_not_first_only() {
        let reads = vec![
            h(b"/data/projects/acme/ok.h", 1, false),
            h(b"relative/bad.h", 2, false),
            h(b"/double//slash.h", 3, false),
        ];
        let errs = NativeHeaderClosure::capture(&reads).expect_err("refuses");
        assert_eq!(errs.len(), 2, "all violations, never first-only");
        assert!(
            errs.iter()
                .all(|v| v.reason_code == VIOLATED_NONCANONICAL_PATH)
        );
    }

    #[test]
    fn closed_view_reports_every_violation_class() {
        let declared = NativeHeaderClosure::capture(&[
            h(b"/data/projects/acme/src/a.h", 1, false),
            h(b"/data/projects/acme/gen/config.h", 2, true),
        ])
        .expect("ok");

        // Clean run: eligible.
        let clean = vec![h(b"/data/projects/acme/src/a.h", 1, false)];
        assert_eq!(enforce_closed_view(&declared, &clean), Ok(()));

        // Undeclared read AND content mismatch on a declared header:
        // BOTH reported.
        let dirty = vec![
            h(b"/data/projects/acme/sneaky.h", 5, false), // undeclared
            h(b"/data/projects/acme/gen/config.h", 6, true), // mismatch
        ];
        let errs = enforce_closed_view(&declared, &dirty).expect_err("violations");
        assert_eq!(errs.len(), 2);
        assert_eq!(errs[0].reason_code, VIOLATED_UNDECLARED_READ);
        assert_eq!(errs[1].reason_code, VIOLATED_CONTENT_MISMATCH);

        // Duplicate undeclared reads report once per distinct path.
        let duped = vec![
            h(b"/data/projects/acme/sneaky.h", 5, false),
            h(b"/data/projects/acme/sneaky.h", 5, false),
        ];
        let errs = enforce_closed_view(&declared, &duped).expect_err("violations");
        assert_eq!(errs.len(), 1);
    }
}
