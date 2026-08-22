//! Structured directive validation + native-link closure (bead N014;
//! plan §196 Epic N; T045 mutation/negative-lookup scenarios; consumes
//! [`crate::directive_manifest::DirectiveManifest`] and the N003
//! output-tree manifest).
//!
//! THE REPLAY GATE, in enforceable form: before a cached run's stdout
//! is exposed to Cargo, EVERY path-valued directive must resolve to one
//! of exactly three admissible classes (R122):
//!
//! 1. **Declared generated output** — the path lives inside the
//!    installed post-run tree: [`ValidationPolicy::installed_tree_prefix`]
//!    joined with an N003 manifest entry equals the reference, or the
//!    reference is a directory CONTAINING such an entry;
//! 2. **Immutable toolchain/native dataset** — explicitly registered
//!    before the fact as immutable for every consumer;
//! 3. **Captured host-bound input** — explicitly captured at the same
//!    canonical path for every consumer.
//!
//! Anything else blocks serving — typed, per-directive, naming the
//! offending `seq`. There is no "probably fine" arm: a mutated
//! directive (`/usr/evil`), a relative escape (`../`, `./`), or a
//! negative lookup (prefix-admissible but absent from the captured
//! tree) all fail closed with DISTINCT verdicts audits can quote.
//!
//! The **native-link closure** models `rustc-link-lib` implicit search
//! declaratively: each library row records whether an explicit
//! `rustc-link-search` preceded it; a lib without one is a NEGATIVE
//! CANDIDATE — recorded in the closure, never silently dropped.
//!
//! Exact-bytes preservation downstream (rustc-env / metadata values) is
//! asserted against the N004 reconstruction — validation proves the
//! bytes survive; it never transforms them.

use crate::directive_manifest::{DirectiveKind, DirectiveManifest, ManifestEntry};
use crate::output_manifest::{OutputEntry, OutputTreeManifest};

/// Version tag stamped on validation reports.
pub const DIRECTIVE_VALIDATION_VERSION: u32 = 1;

/// Admissible resolution classes for a directive-referenced path (R122).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// Inside the installed post-run tree (declared generated output).
    DeclaredGeneratedOutput,
    /// Registered immutable toolchain/native dataset.
    ImmutableToolchainAsset,
    /// Captured host-bound input at a canonical path shared by every
    /// consumer.
    CapturedHostInput,
}

/// Verdict for one referenced path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathVerdict {
    /// Resolves to an admissible class.
    Admissible(PathClass),
    /// Exists outside every admissible class.
    NonPortable,
    /// Depends on ambient state replay cannot reproduce.
    Volatile {
        /// Stable short reason code.
        reason: &'static str,
    },
}

/// The validation policy: canonical prefixes and registered sets. Byte
/// matching is literal after leading-`./` normalization; no globs, no
/// environment expansion, no case folds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationPolicy {
    /// Canonical location where the post-run tree was INSTALLED on this
    /// consumer; N003 manifest entries are interpreted RELATIVE to it.
    pub installed_tree_prefix: Vec<u8>,
    /// Exact paths registered as immutable toolchain/native datasets.
    pub immutable_toolchain_paths: Vec<Vec<u8>>,
    /// Canonical DIRECTORY prefixes registered as immutable
    /// toolchain/native datasets (search paths point at directories;
    /// exact-file admission alone cannot admit them).
    pub immutable_toolchain_prefixes: Vec<Vec<u8>>,
    /// Exact paths registered as captured host-bound inputs.
    pub captured_host_inputs: Vec<Vec<u8>>,
}

impl ValidationPolicy {
    /// Classify one referenced path against this policy.
    #[must_use]
    pub fn classify(&self, path: &[u8]) -> PathVerdict {
        // Volatility is judged on the RAW path: normalization erases
        // exactly the evidence (`./` collapse) that proves it.
        if path.starts_with(b"../") || path == b".." {
            return PathVerdict::Volatile {
                reason: "relative parent escape",
            };
        }
        if path == b"." || path.starts_with(b"./") {
            return PathVerdict::Volatile {
                reason: "working-directory-relative",
            };
        }
        let normalized = normalize(path);
        if starts_with_dir(&normalized, &self.installed_tree_prefix) {
            return PathVerdict::Admissible(PathClass::DeclaredGeneratedOutput);
        }
        if self
            .immutable_toolchain_paths
            .contains(&normalized.to_vec())
            || self
                .immutable_toolchain_prefixes
                .iter()
                .any(|p| starts_with_dir(&normalized, p))
        {
            return PathVerdict::Admissible(PathClass::ImmutableToolchainAsset);
        }
        if self.captured_host_inputs.contains(&normalized.to_vec()) {
            return PathVerdict::Admissible(PathClass::CapturedHostInput);
        }
        PathVerdict::NonPortable
    }
}

fn starts_with_dir(path: &[u8], prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && (path == prefix || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/')))
}

/// Normalize repeated leading `./`; everything else byte-exact.
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut p = path.to_vec();
    while p.starts_with(b"./") {
        p.drain(0..2);
    }
    p
}

/// One directive-referenced path found in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectivePathRef {
    /// Shared arrival sequence of the directive line.
    pub seq: u64,
    /// Registry key that carried the path.
    pub key: Vec<u8>,
    /// Referenced path bytes, byte-exact (link-search kind prefix
    /// stripped).
    pub path: Vec<u8>,
}

/// Keys whose values are consumed by cargo (never path-bearing for our
/// purposes) — everything else with a value is validated as a potential
/// path carrier, so UNKNOWN directives cannot escape the gate.
const CONSUMED_NON_PATH_KEYS: [&[u8]; 7] = [
    b"rustc-env",
    b"rustc-flags",
    b"rustc-link-lib",
    b"rustc-cdylib-link-arg",
    b"warning",
    b"metadata",
    b"rerun-if-env-changed",
];

/// Whether a directive key's VALUE may carry a path requiring closure.
#[must_use]
pub fn carries_path(key: &[u8]) -> bool {
    !CONSUMED_NON_PATH_KEYS.contains(&key)
}

/// Strip a leading `[kind=]` prefix from `rustc-link-search` values
/// (known kinds only; anything else is part of the path itself).
fn strip_search_kind(value: &[u8]) -> &[u8] {
    const KINDS: [&[u8]; 5] = [b"native", b"crate", b"framework", b"all", b"dependency"];
    if let Some(eq) = value.iter().position(|&b| b == b'=') {
        let head = &value[..eq];
        if KINDS.contains(&head) {
            return &value[eq + 1..];
        }
    }
    value
}

/// Extract every path-valued reference from a directive manifest.
#[must_use]
pub fn extract_path_refs(manifest: &DirectiveManifest) -> Vec<DirectivePathRef> {
    let mut refs = Vec::new();
    for entry in &manifest.entries {
        if let ManifestEntry::Directive {
            seq,
            key,
            value: Some(v),
            ..
        } = entry
            && carries_path(key)
        {
            let path = if key == b"rustc-link-search" {
                strip_search_kind(v).to_vec()
            } else {
                v.clone()
            };
            refs.push(DirectivePathRef {
                seq: *seq,
                key: key.clone(),
                path,
            });
        }
    }
    refs
}

/// A typed violation blocking stdout exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// A referenced path resolved to nothing admissible.
    NonPortablePath {
        /// Offending directive's sequence.
        seq: u64,
        /// The offending path bytes.
        path: Vec<u8>,
    },
    /// A referenced path depends on ambient state.
    VolatilePath {
        /// Offending directive's sequence.
        seq: u64,
        /// The offending path bytes.
        path: Vec<u8>,
        /// Stable short reason code.
        reason: &'static str,
    },
    /// Prefix-admissible but ABSENT from the installed post-run tree:
    /// the captured tree does not back the promise.
    NegativeLookup {
        /// Offending directive's sequence.
        seq: u64,
        /// The missing path bytes.
        path: Vec<u8>,
    },
    /// A link-library with no preceding explicit search path: negative
    /// candidate in the downstream link closure.
    UnresolvedLinkLib {
        /// Offending directive's sequence.
        seq: u64,
        /// Library name bytes.
        name: Vec<u8>,
    },
}

/// One native-link closure row (`rustc-link-lib` semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkClosureEntry {
    /// Shared arrival sequence.
    pub seq: u64,
    /// Linkage kind bytes (`static`, `dylib`, …).
    pub kind: Vec<u8>,
    /// Library name bytes (post `kind=` split).
    pub name: Vec<u8>,
    /// Whether an explicit `rustc-link-search` preceded this entry.
    pub explicit_search_seen: bool,
}

/// Compute the downstream native-link closure, in arrival order.
#[must_use]
pub fn link_closure(manifest: &DirectiveManifest) -> Vec<LinkClosureEntry> {
    let mut closure = Vec::new();
    let mut search_seen = false;
    for entry in &manifest.entries {
        match entry {
            ManifestEntry::Directive {
                kind: DirectiveKind::RustcLinkSearch,
                ..
            } => search_seen = true,
            ManifestEntry::Directive {
                seq,
                kind: DirectiveKind::RustcLinkLib,
                value: Some(v),
                ..
            } => {
                let (k, n) = match v.iter().position(|&b| b == b'=') {
                    Some(eq) => (&v[..eq], &v[eq + 1..]),
                    None => (&b"dylib"[..], &v[..]),
                };
                closure.push(LinkClosureEntry {
                    seq: *seq,
                    kind: k.to_vec(),
                    name: n.to_vec(),
                    explicit_search_seen: search_seen,
                });
            }
            _ => {}
        }
    }
    closure
}

/// Full replay-readiness validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayValidation {
    /// Version tag ([`DIRECTIVE_VALIDATION_VERSION`]).
    pub version: u32,
    /// Every violation found (empty ⇒ ready).
    pub violations: Vec<Violation>,
    /// The native-link closure rows.
    pub link_closure: Vec<LinkClosureEntry>,
}

impl ReplayValidation {
    /// Whether stdout may be exposed to Cargo (zero violations).
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Join policy prefix with an installed-tree entry path.
fn installed_absolute(policy: &ValidationPolicy, entry: &OutputEntry) -> Vec<u8> {
    let mut v = policy.installed_tree_prefix.clone();
    v.push(b'/');
    v.extend_from_slice(&entry.path);
    v
}

/// Does one installed entry back a directive-referenced path? Exact
/// equality (file reference) or containment (directory reference: the
/// entry lies under it).
fn backs_reference(policy: &ValidationPolicy, entry: &OutputEntry, reference: &[u8]) -> bool {
    let abs = installed_absolute(policy, entry);
    if abs == reference {
        return true;
    }
    abs.starts_with(reference) && abs.get(reference.len()) == Some(&b'/')
}

/// Validate a captured directive manifest for replay readiness.
///
/// Checks per directive: path classifies admissibly; declared outputs
/// are BACKED by the captured tree (negative lookups refuse);
/// link-libs without preceding explicit search become recorded negative
/// candidates. Byte-exactness downstream rides the N004 reconstruction.
#[must_use]
pub fn validate_replay(
    manifest: &DirectiveManifest,
    installed_tree: &OutputTreeManifest,
    policy: &ValidationPolicy,
) -> ReplayValidation {
    let mut violations = Vec::new();
    for r in &extract_path_refs(manifest) {
        match policy.classify(&r.path) {
            PathVerdict::Admissible(PathClass::DeclaredGeneratedOutput) => {
                let backed = installed_tree
                    .out_dir_entries
                    .iter()
                    .any(|e| backs_reference(policy, e, &r.path))
                    || installed_tree
                        .cache_entries
                        .iter()
                        .any(|e| backs_reference(policy, e, &r.path));
                if !backed {
                    violations.push(Violation::NegativeLookup {
                        seq: r.seq,
                        path: r.path.clone(),
                    });
                }
            }
            PathVerdict::Admissible(_) => {}
            PathVerdict::NonPortable => violations.push(Violation::NonPortablePath {
                seq: r.seq,
                path: r.path.clone(),
            }),
            PathVerdict::Volatile { reason } => violations.push(Violation::VolatilePath {
                seq: r.seq,
                path: r.path.clone(),
                reason,
            }),
        }
    }

    let closure = link_closure(manifest);
    for entry in &closure {
        if !entry.explicit_search_seen {
            violations.push(Violation::UnresolvedLinkLib {
                seq: entry.seq,
                name: entry.name.clone(),
            });
        }
    }

    ReplayValidation {
        version: DIRECTIVE_VALIDATION_VERSION,
        violations,
        link_closure: closure,
    }
}

/// Sequencing law, executable form: stdout exposure MUST gate behind a
/// READY validation. Refusal carries the full report.
///
/// # Errors
/// Returns the report when not ready.
pub fn gate_stdout_exposure(validation: &ReplayValidation) -> Result<(), &ReplayValidation> {
    if validation.ready() {
        Ok(())
    } else {
        Err(validation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive_manifest::extract_directives;
    use crate::output_manifest::OutputEntry;
    use crate::stream_chunker::{CanonicalObservation as Obs, StdStream};

    fn stdout_line(seq: u64, text: &[u8]) -> Obs {
        let mut bytes = text.to_vec();
        bytes.push(b'\n');
        Obs::Line {
            stream: StdStream::Stdout,
            seq,
            bytes,
        }
    }

    fn manifest_of(lines: &[&[u8]]) -> DirectiveManifest {
        let obs: Vec<Obs> = lines
            .iter()
            .enumerate()
            .map(|(i, l)| stdout_line(i as u64 + 1, l))
            .collect();
        extract_directives(&obs).expect("ordered transcript")
    }

    fn tree(entries: &[(&str, u64)]) -> OutputTreeManifest {
        OutputTreeManifest::new(
            entries
                .iter()
                .map(|(p, l)| OutputEntry::new(*p, *l))
                .collect(),
            Vec::new(),
        )
        .expect("valid tree")
    }

    fn base_policy() -> ValidationPolicy {
        ValidationPolicy {
            installed_tree_prefix: b"/snapshot".to_vec(),
            immutable_toolchain_paths: vec![b"/opt/toolchain/libgolden.a".to_vec()],
            immutable_toolchain_prefixes: vec![b"/opt/toolchain".to_vec()],
            captured_host_inputs: vec![b"/host/captured/sysroot".to_vec()],
        }
    }

    /// T045 positive: all three classes admit, zero violations, gate
    /// opens. Declared output is BACKED by the captured tree entry
    /// (`/snapshot` + `out/libearly.a`).
    #[test]
    fn t045_all_three_classes_admit_and_gate_opens() {
        let m = manifest_of(&[
            b"cargo:rustc-link-search=native=/snapshot/out",
            b"cargo:rustc-link-search=native=/opt/toolchain",
            b"cargo:rustc-link-search=native=/host/captured/sysroot",
            b"cargo:rustc-link-lib=static=golden_native",
            b"cargo:rustc-env=GOLDEN=yes",
            b"cargo:metadata=FEATURE=on",
        ]);
        let t = tree(&[("out/libgolden_native.a", 4096)]);
        let report = validate_replay(&m, &t, &base_policy());
        assert!(report.ready(), "violations: {:?}", report.violations);
        assert_eq!(report.link_closure.len(), 1);
        assert!(report.link_closure[0].explicit_search_seen);
        assert_eq!(gate_stdout_exposure(&report), Ok(()));
    }

    /// T045 mutation: ambient absolute swap refuses NONPORTABLE even
    /// though it exists on the capturing host.
    #[test]
    fn t045_mutated_link_search_to_ambient_path_is_nonportable() {
        let m = manifest_of(&[b"cargo:rustc-link-search=native=/usr/lib/evil"]);
        let report = validate_replay(&m, &tree(&[]), &base_policy());
        assert!(!report.ready());
        assert!(report.violations.contains(&Violation::NonPortablePath {
            seq: 1,
            path: b"/usr/lib/evil".to_vec(),
        }));
        assert!(gate_stdout_exposure(&report).is_err());
    }

    /// T045 mutation: relative escapes are VOLATILE — a distinct verdict
    /// from nonportable, covering both escape spellings.
    #[test]
    fn t045_relative_escape_is_volatile_not_merely_nonportable() {
        let m = manifest_of(&[
            b"cargo:rustc-link-search=native=../escape",
            b"cargo:rerun-if-changed=./cwd-relative.rs",
        ]);
        let report = validate_replay(&m, &tree(&[]), &base_policy());
        assert_eq!(report.violations.len(), 2);
        assert!(report.violations.iter().any(|v| matches!(
            v,
            Violation::VolatilePath {
                reason: "relative parent escape",
                ..
            }
        )));
        assert!(report.violations.iter().any(|v| matches!(
            v,
            Violation::VolatilePath {
                reason: "working-directory-relative",
                ..
            }
        )));
    }

    /// T045 negative lookup: prefix-admissible but absent from the
    /// captured tree refuses; present-with-containment passes.
    #[test]
    fn t045_negative_lookup_missing_from_installed_tree() {
        let m = manifest_of(&[b"cargo:rustc-link-search=native=/snapshot/out"]);
        let empty = tree(&[]);
        let bad = validate_replay(&m, &empty, &base_policy());
        assert!(bad.violations.contains(&Violation::NegativeLookup {
            seq: 1,
            path: b"/snapshot/out".to_vec(),
        }));
        // Directory reference is BACKED by any entry contained in it.
        let backed = tree(&[("out/libthing.a", 10)]);
        let good = validate_replay(&m, &backed, &base_policy());
        assert!(good.ready(), "{:?}", good.violations);
    }

    /// T045 negative candidate: link-lib BEFORE any search path is a
    /// recorded unresolved entry; later libs with search pass clean.
    #[test]
    fn t045_link_lib_before_search_is_a_negative_candidate() {
        let m = manifest_of(&[
            b"cargo:rustc-link-lib=static=early",
            b"cargo:rustc-link-search=native=/snapshot/out",
            b"cargo:rustc-link-lib=static=late",
        ]);
        let t = tree(&[("out/libearly.a", 1), ("out/liblate.a", 2)]);
        let report = validate_replay(&m, &t, &base_policy());
        assert_eq!(report.link_closure.len(), 2);
        assert!(!report.link_closure[0].explicit_search_seen);
        assert!(report.link_closure[1].explicit_search_seen);
        assert!(report.violations.contains(&Violation::UnresolvedLinkLib {
            seq: 1,
            name: b"early".to_vec(),
        }));
        assert!(
            !report
                .violations
                .iter()
                .any(|v| matches!(v, Violation::UnresolvedLinkLib { name, .. } if name == b"late"))
        );
    }

    /// MEASURED N004 semantics hold through validation context:
    /// rustc-env/metadata bytes preserved downstream EXACTLY, with the
    /// forwarding partition respected (rustc-env consumed, metadata
    /// forwarded, interior '=' intact).
    #[test]
    fn t045_env_and_metadata_bytes_preserved_downstream() {
        let m = manifest_of(&[
            b"cargo:rustc-env=N011_GOLDEN=1",
            b"cargo:metadata=VERSION==1.0.0-final",
        ]);
        let dep = crate::dep_links::reconstruct_dep_env(b"probe", &m);
        assert_eq!(
            dep.vars,
            vec![(
                b"DEP_PROBE_METADATA".to_vec(),
                b"VERSION==1.0.0-final".to_vec()
            )],
            "consumed kinds excluded; metadata forwarded byte-exactly"
        );
        // Raw-line exactness survives extraction round-trip.
        for entry in &m.entries {
            if let ManifestEntry::Directive { raw_line, .. } = entry {
                assert!(raw_line.ends_with(b"\n"));
            }
        }
    }

    /// Unknown-key path carriers do NOT escape the gate.
    #[test]
    fn t045_unknown_keys_with_path_values_are_still_validated() {
        let m = manifest_of(&[b"cargo:future_path_directive=/somewhere/ambient"]);
        let report = validate_replay(&m, &tree(&[]), &base_policy());
        assert!(report.violations.iter().any(
            |v| matches!(v, Violation::NonPortablePath { path, .. } if path == b"/somewhere/ambient")
        ));
    }

    /// Kind-prefix stripping: `native=` is removed, unknown prefixes
    /// stay part of the path (and thus fail closed).
    #[test]
    fn t045_link_search_kind_stripping_is_conservative() {
        let known = manifest_of(&[b"cargo:rustc-link-search=native=/snapshot/out"]);
        assert!(validate_replay(&known, &tree(&[("out/l.a", 1)]), &base_policy()).ready());
        let weird = manifest_of(&[b"cargo:rustc-link-search=weird=/snapshot/out"]);
        let report = validate_replay(&weird, &tree(&[("out/l.a", 1)]), &base_policy());
        assert!(
            report
                .violations
                .iter()
                .any(|v| matches!(v, Violation::NonPortablePath { path, .. } if path == b"weird=/snapshot/out")),
            "unknown kind prefix must be treated as path bytes"
        );
    }

    /// Segment-boundary integrity: `/snapshot` must not back `about/x`.
    #[test]
    fn t045_prefix_matching_respects_segment_boundaries() {
        let m = manifest_of(&[b"cargo:dep-info=/snapshotabout/x"]);
        let report = validate_replay(&m, &tree(&[("about/x", 1)]), &base_policy());
        assert!(!report.ready(), "segment-boundary spoof must fail closed");
    }
}
