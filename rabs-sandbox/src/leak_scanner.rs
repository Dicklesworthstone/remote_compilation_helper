//! Path leak scanner for outputs and metadata (bead D012; invariant
//! I20; plan §58; risk R42; builds on the D002 primitive).
//!
//! Every surface an action produces — artifacts, metadata, compiler
//! events, generated source, dep-info — is scanned for hidden-world
//! strings: real worktree roots, user homes, worker temp/CAS roots,
//! hidden operation/attempt/snapshot staging paths, hostnames,
//! usernames, actual target/build dirs, secret mount backing paths.
//! Findings CLASSIFY (the response differs radically by class):
//!
//! - `AdmittedCanonical` — the path is a sanctioned canonical form
//!   under the family's BuildPathSemanticPolicy: no leak;
//! - `PresentationOnlyTranslated` — appears only in a
//!   subscriber-translated presentation surface: renderable away;
//! - `RemappableDebugMetadata` — debug-section-only reference:
//!   remappable, artifact still shareable after remap;
//! - `KeyRelevantSemanticLeakage` — a hidden value reached a
//!   key-participating surface: the key itself is suspect;
//! - `OutputSemanticPathSensitivity` — LOADABLE/runtime-visible bytes
//!   embed the path: output semantics depend on it;
//! - `PrivacySecretIncident` — a secret backing path or username
//!   escaped: incident, never just a cache decision;
//! - `NonCanonicalLaunchEvidence` — divergent Cargo metadata hashes
//!   prove Cargo did not actually run canonically.
//!
//! **Ambiguous loadable-data leakage loses portable authority**: the
//! disposition routes to the D030 path-preserving lane, never to a
//! canonical shared hit.

use crate::layout::leaks_backing_path;

/// The surface a finding was seen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Surface {
    LoadableArtifact,
    DebugMetadata,
    CompilerEvents,
    GeneratedSource,
    DepInfo,
    PresentationTranscript,
    CargoMetadataHash,
}

/// The hidden-world pattern classes the scanner hunts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenWorld {
    /// Real worktree roots (per-agent checkouts).
    pub worktree_roots: Vec<String>,
    /// User home directories.
    pub user_homes: Vec<String>,
    /// Worker temp/CAS/staging roots (attempt/operation dirs).
    pub staging_roots: Vec<String>,
    /// Host/user names.
    pub identities: Vec<String>,
    /// Secret mount BACKING paths (never the /run/rabs-secrets view).
    pub secret_backing_roots: Vec<String>,
}

/// Finding classification (the bead's seven classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum LeakClass {
    AdmittedCanonical,
    PresentationOnlyTranslated,
    RemappableDebugMetadata,
    KeyRelevantSemanticLeakage,
    OutputSemanticPathSensitivity,
    PrivacySecretIncident,
    NonCanonicalLaunchEvidence,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakFinding {
    /// Which surface.
    pub surface: Surface,
    /// The classification.
    pub class: LeakClass,
    /// The matched hidden value.
    pub matched: String,
}

/// Disposition after scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDisposition {
    /// Clean (or admitted/translatable only): canonical authority holds.
    CanonicalAuthorityHolds,
    /// Remap required first; shareable after.
    RemapThenShare,
    /// Portable authority LOST: route to the path-preserving lane.
    PathPreservingLane,
    /// Incident: secrets/privacy escaped — quarantine + report.
    Incident,
}

// Keep auxiliary matching memory bounded even for an unusually large hidden
// world. Exceeding this budget falls back to the original complete scanner;
// it must never truncate the pattern inventory or return a clean verdict.
const MAX_MATCH_STATES: usize = 16_384;

#[derive(Default)]
struct MatchState {
    // Sorted sparse byte edges: no 256-entry table for every path prefix.
    edges: Vec<(u8, usize)>,
    failure: usize,
}

impl MatchState {
    fn edge(&self, byte: u8) -> Result<usize, usize> {
        self.edges.binary_search_by_key(&byte, |edge| edge.0)
    }
}

fn advance(states: &[MatchState], mut state: usize, byte: u8) -> usize {
    loop {
        if let Ok(edge) = states[state].edge(byte) {
            return states[state].edges[edge].1;
        }
        if state == 0 {
            return 0;
        }
        state = states[state].failure;
    }
}

/// Presence of every literal byte pattern, including overlapping/suffix
/// matches. Findings need presence, not every occurrence: mark each reached
/// state and its failure ancestors only once. Encountering a marked state ends
/// that walk because all of its ancestors are already marked. Repeated matches
/// cannot create an occurrence list proportional to artifact size times the
/// number of nested patterns. Stop once every distinct pattern has matched.
fn matching_patterns(bytes: &[u8], patterns: &[&str], state_limit: usize) -> Vec<bool> {
    if bytes.is_empty() {
        return vec![false; patterns.len()];
    }
    // Retain the existing vectorized substring search for the one-pattern
    // case. Empty patterns have never been evidence of a leak.
    if patterns
        .iter()
        .filter(|pattern| !pattern.is_empty())
        .count()
        <= 1
    {
        return literal_matches(bytes, patterns);
    }
    let mut states = vec![MatchState::default()];
    let mut terminals = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let mut state = 0;
        for byte in pattern.bytes() {
            state = match states[state].edge(byte) {
                Ok(edge) => states[state].edges[edge].1,
                Err(edge) => {
                    if states.len() >= state_limit {
                        return literal_matches(bytes, patterns);
                    }
                    let next = states.len();
                    states.push(MatchState::default());
                    states[state].edges.insert(edge, (byte, next));
                    next
                }
            };
        }
        terminals.push(state);
    }
    // Failure links always target a shorter prefix. Build breadth-first so a
    // child's failure chain already exists; creation order is NOT enough.
    let mut breadth_first: Vec<usize> = states[0].edges.iter().map(|edge| edge.1).collect();
    let mut cursor = 0;
    while cursor < breadth_first.len() {
        let parent = breadth_first[cursor];
        // Clone at most 256 sparse edges to permit updating child states.
        for (byte, child) in states[parent].edges.clone() {
            states[child].failure = advance(&states, states[parent].failure, byte);
            breadth_first.push(child);
        }
        cursor += 1;
    }
    let mut terminal = vec![false; states.len()];
    for &state in &terminals {
        if state != 0 {
            terminal[state] = true;
        }
    }
    let mut remaining = terminal.iter().filter(|matched| **matched).count();
    let mut seen = vec![false; states.len()];
    seen[0] = true;
    let mut state = 0;
    let mut offset = 0;
    while offset < bytes.len() {
        if state == 0 {
            // Hidden paths commonly share '/' as their first byte. Skip a
            // root-state run with memchr instead of inspecting every clean
            // artifact byte in Rust. Never skip while a prefix is in flight.
            let skip = match states[0].edges.as_slice() {
                [(a, _)] => memchr::memchr(*a, &bytes[offset..]),
                [(a, _), (b, _)] => memchr::memchr2(*a, *b, &bytes[offset..]),
                [(a, _), (b, _), (c, _)] => memchr::memchr3(*a, *b, *c, &bytes[offset..]),
                _ => Some(0),
            };
            let Some(skip) = skip else { break };
            offset += skip;
        }
        state = advance(&states, state, bytes[offset]);
        let mut suffix = state;
        while !seen[suffix] {
            seen[suffix] = true;
            if terminal[suffix] {
                remaining -= 1;
            }
            suffix = states[suffix].failure;
        }
        offset += 1;
        if remaining == 0 {
            break;
        }
    }
    terminals
        .into_iter()
        .map(|state| state != 0 && seen[state])
        .collect()
}

fn literal_matches(bytes: &[u8], patterns: &[&str]) -> Vec<bool> {
    patterns
        .iter()
        .map(|pattern| leaks_backing_path(bytes, &[*pattern]))
        .collect()
}

/// Scan one surface's bytes against the hidden world.
#[must_use]
pub fn scan_surface(
    surface: Surface,
    bytes: &[u8],
    hidden: &HiddenWorld,
    canonical_launch_verified: bool,
) -> Vec<LeakFinding> {
    // Scan across classes together, but retain the historical class/list order
    // and duplicates in the report. A shared byte string can be both a secret
    // backing root and a worktree root; neither finding may hide the other.
    let patterns: Vec<&str> = hidden
        .secret_backing_roots
        .iter()
        .chain(&hidden.identities)
        .chain(&hidden.worktree_roots)
        .chain(&hidden.user_homes)
        .chain(&hidden.staging_roots)
        .map(String::as_str)
        .collect();
    let mut matched = matching_patterns(bytes, &patterns, MAX_MATCH_STATES).into_iter();
    let mut findings = Vec::new();
    let mut check = |patterns: &[String], class_for: &dyn Fn(Surface) -> LeakClass| {
        for pattern in patterns {
            if matched
                .next()
                .expect("one presence result per hidden pattern")
            {
                findings.push(LeakFinding {
                    surface,
                    class: class_for(surface),
                    matched: pattern.clone(),
                });
            }
        }
    };
    // Secret backing paths: ALWAYS an incident, any surface.
    check(&hidden.secret_backing_roots, &|_| {
        LeakClass::PrivacySecretIncident
    });
    // Identities (host/user names): privacy incident on loadable
    // surfaces, remappable in debug metadata, presentation-only in
    // transcripts.
    check(&hidden.identities, &|s| match s {
        Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
        Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
        _ => LeakClass::PrivacySecretIncident,
    });
    // Worktree/home/staging paths: class depends on the surface.
    for patterns in [
        &hidden.worktree_roots,
        &hidden.user_homes,
        &hidden.staging_roots,
    ] {
        check(patterns, &|s| match s {
            Surface::LoadableArtifact => LeakClass::OutputSemanticPathSensitivity,
            Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
            Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
            Surface::DepInfo | Surface::GeneratedSource | Surface::CompilerEvents => {
                LeakClass::KeyRelevantSemanticLeakage
            }
            Surface::CargoMetadataHash => LeakClass::NonCanonicalLaunchEvidence,
        });
    }
    // Divergent Cargo metadata hashes: evidence Cargo was not launched
    // canonically, independent of pattern matches.
    if surface == Surface::CargoMetadataHash && !canonical_launch_verified {
        findings.push(LeakFinding {
            surface,
            class: LeakClass::NonCanonicalLaunchEvidence,
            matched: "metadata-hash-divergence".into(),
        });
    }
    findings
}

/// Fold findings into the action's disposition. Worst class wins;
/// ambiguity (any loadable/key-relevant leak) loses portable authority.
#[must_use]
pub fn disposition(findings: &[LeakFinding]) -> ScanDisposition {
    if findings
        .iter()
        .any(|f| f.class == LeakClass::PrivacySecretIncident)
    {
        return ScanDisposition::Incident;
    }
    if findings.iter().any(|f| {
        matches!(
            f.class,
            LeakClass::OutputSemanticPathSensitivity
                | LeakClass::KeyRelevantSemanticLeakage
                | LeakClass::NonCanonicalLaunchEvidence
        )
    }) {
        return ScanDisposition::PathPreservingLane;
    }
    if findings
        .iter()
        .any(|f| f.class == LeakClass::RemappableDebugMetadata)
    {
        return ScanDisposition::RemapThenShare;
    }
    ScanDisposition::CanonicalAuthorityHolds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_matches(bytes: &[u8], patterns: &[&str]) -> Vec<bool> {
        patterns
            .iter()
            .map(|pattern| {
                !pattern.is_empty()
                    && bytes
                        .windows(pattern.len())
                        .any(|window| window == pattern.as_bytes())
            })
            .collect()
    }

    #[test]
    fn empty_and_single_pattern_inventories_preserve_literal_behavior() {
        for patterns in [vec![], vec![""], vec!["", ""], vec!["a"], vec!["", "a", ""]] {
            for bytes in [&b""[..], &b"ab"[..], &b"clean"[..], &b"\xff\0"[..]] {
                assert_eq!(
                    matching_patterns(bytes, &patterns, MAX_MATCH_STATES),
                    reference_matches(bytes, &patterns)
                );
            }
        }
    }

    #[test]
    fn root_prefilters_retain_every_start_byte_and_inflight_prefix() {
        for patterns in [
            vec!["/root", "/root/child", "/secret"],
            vec!["/root", "user", "user/root"],
            vec!["/root", "user", "host", "host/root"],
            vec!["/root", "user", "host", "tmp", "tmp/root"],
        ] {
            for prefix in [0, 1, 15, 16, 31, 32, 63, 64, 255] {
                let mut bytes = vec![0xff; prefix];
                bytes.extend_from_slice(b"/roo/root/child user/root host/root tmp/root /secret");
                let expected = reference_matches(&bytes, &patterns);
                assert!(expected.iter().all(|matched| *matched));
                assert_eq!(
                    matching_patterns(&bytes, &patterns, MAX_MATCH_STATES),
                    expected
                );
                assert_eq!(
                    matching_patterns(&vec![0xff; prefix], &patterns, MAX_MATCH_STATES),
                    vec![false; patterns.len()]
                );
            }
        }
    }

    #[test]
    fn overlapping_prefixes_suffixes_duplicates_and_empty_patterns_keep_presence() {
        for patterns in [
            vec!["abcd", "b", "bc", "cd", "d", "abcd", ""],
            vec!["he", "she", "his", "hers", "ers", "s", ""],
            vec!["aaaa", "aaa", "aa", "a", "ba", "aba", "a"],
            vec!["abcef", "cef", "ef", "f", "bce", "no-match"],
        ] {
            for bytes in [
                &b""[..],
                &b"abcd"[..],
                &b"ushers"[..],
                &b"aaaaabaaaa"[..],
                &b"abzabcef"[..],
            ] {
                assert_eq!(
                    matching_patterns(bytes, &patterns, MAX_MATCH_STATES),
                    reference_matches(bytes, &patterns),
                    "{patterns:?} / {bytes:?}"
                );
            }
        }
    }

    fn binary_words(max_len: usize) -> Vec<String> {
        let mut words = vec![String::new()];
        for len in 1..=max_len {
            for bits in 0..(1_usize << len) {
                words.push(
                    (0..len)
                        .map(|bit| if bits & (1 << bit) == 0 { 'a' } else { 'b' })
                        .collect(),
                );
            }
        }
        words
    }

    #[test]
    fn exhaustive_small_alphabet_matches_a_naive_literal_oracle() {
        let mut owned = binary_words(4);
        // Include duplicate and overlapping terminals, in both insertion
        // orders. Suffix states can be allocated AFTER their longer prefixes.
        owned.extend(["aba".to_owned(), String::new()]);
        for reverse in [false, true] {
            let mut patterns: Vec<&str> = owned.iter().map(String::as_str).collect();
            if reverse {
                patterns.reverse();
            }
            for bytes in binary_words(7) {
                let expected = reference_matches(bytes.as_bytes(), &patterns);
                for limit in [0, 1, 2, 8, MAX_MATCH_STATES] {
                    assert_eq!(
                        matching_patterns(bytes.as_bytes(), &patterns, limit),
                        expected,
                        "limit={limit} reverse={reverse} input={bytes:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn raw_binary_unicode_and_nul_matches_do_not_require_text_decoding() {
        let patterns = ["é", "ø", "\0", "/tmp/秘密", "秘密", "absent", "é"];
        for offset in 0..16 {
            let mut bytes = vec![0xff; offset];
            bytes.extend_from_slice("é\0/tmp/秘密\0ø".as_bytes());
            bytes.extend_from_slice(&[0xfe, 0xf0, 0x80, b'/']);
            assert_eq!(
                matching_patterns(&bytes, &patterns, MAX_MATCH_STATES),
                reference_matches(&bytes, &patterns)
            );
        }
    }

    #[test]
    fn repeated_nested_matches_do_not_hide_a_late_secret_or_an_absent_pattern() {
        let mut owned: Vec<String> = (1..=128).map(|len| "a".repeat(len)).collect();
        owned.extend(["late-secret".into(), "not-present".into(), String::new()]);
        let patterns: Vec<&str> = owned.iter().map(String::as_str).collect();
        let mut bytes = vec![b'a'; 16 * 1024];
        bytes.extend_from_slice(b"late-secret");
        let mut expected = vec![true; 129];
        expected.extend([false, false]);
        assert_eq!(
            matching_patterns(&bytes, &patterns, MAX_MATCH_STATES),
            expected
        );
    }

    #[test]
    fn memory_budget_fallback_never_drops_later_patterns() {
        let oversized = "x".repeat(MAX_MATCH_STATES + 1);
        let patterns = ["first", oversized.as_str(), "secret", "first", ""];
        for bytes in [&b"first secret"[..], &b"secret"[..], &b"clean"[..]] {
            assert_eq!(
                matching_patterns(bytes, &patterns, MAX_MATCH_STATES),
                reference_matches(bytes, &patterns)
            );
        }
    }

    #[test]
    fn deterministic_binary_corpus_matches_literal_search() {
        let mut seed = 0x7261_6273_u64;
        let mut next = || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 32) as u8
        };
        for _ in 0..256 {
            let mut bytes: Vec<u8> = (0..256).map(|_| next()).collect();
            let owned: Vec<String> = (0..32)
                .map(|_| {
                    let len = usize::from(next() % 16);
                    (0..len)
                        .map(|_| ['a', 'b', '/', '\0', 'é'][usize::from(next() % 5)])
                        .collect()
                })
                .collect();
            // Mix guaranteed hits with arbitrary binary and absent strings.
            for pattern in owned.iter().step_by(3) {
                bytes.extend_from_slice(pattern.as_bytes());
                bytes.push(0xff);
            }
            let patterns: Vec<&str> = owned.iter().map(String::as_str).collect();
            assert_eq!(
                matching_patterns(&bytes, &patterns, MAX_MATCH_STATES),
                reference_matches(&bytes, &patterns)
            );
        }
    }

    #[test]
    fn all_surface_classes_preserve_finding_order_duplicates_and_launch_evidence() {
        let hidden = HiddenWorld {
            secret_backing_roots: vec!["shared".into(), "shared".into(), String::new()],
            identities: vec!["shared".into(), "absent".into()],
            worktree_roots: vec!["shared".into(), "hare".into()],
            user_homes: vec!["red".into()],
            staging_roots: vec!["shared".into(), "unmatched".into()],
        };
        for surface in [
            Surface::LoadableArtifact,
            Surface::DebugMetadata,
            Surface::CompilerEvents,
            Surface::GeneratedSource,
            Surface::DepInfo,
            Surface::PresentationTranscript,
            Surface::CargoMetadataHash,
        ] {
            let identity_class = match surface {
                Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
                Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
                _ => LeakClass::PrivacySecretIncident,
            };
            let path_class = match surface {
                Surface::LoadableArtifact => LeakClass::OutputSemanticPathSensitivity,
                Surface::DebugMetadata => LeakClass::RemappableDebugMetadata,
                Surface::PresentationTranscript => LeakClass::PresentationOnlyTranslated,
                Surface::CargoMetadataHash => LeakClass::NonCanonicalLaunchEvidence,
                _ => LeakClass::KeyRelevantSemanticLeakage,
            };
            for canonical in [false, true] {
                let mut expected: Vec<LeakFinding> = [
                    ("shared", LeakClass::PrivacySecretIncident),
                    ("shared", LeakClass::PrivacySecretIncident),
                    ("shared", identity_class),
                    ("shared", path_class),
                    ("hare", path_class),
                    ("red", path_class),
                    ("shared", path_class),
                ]
                .into_iter()
                .map(|(matched, class)| LeakFinding {
                    surface,
                    class,
                    matched: matched.into(),
                })
                .collect();
                if surface == Surface::CargoMetadataHash && !canonical {
                    expected.push(LeakFinding {
                        surface,
                        class: LeakClass::NonCanonicalLaunchEvidence,
                        matched: "metadata-hash-divergence".into(),
                    });
                }
                let actual = scan_surface(surface, b"shared shared", &hidden, canonical);
                assert_eq!(actual, expected, "{surface:?}/{canonical}");
                assert_eq!(disposition(&actual), ScanDisposition::Incident);
                let clean = scan_surface(surface, b"", &hidden, canonical);
                assert_eq!(
                    clean.len(),
                    usize::from(surface == Surface::CargoMetadataHash && !canonical)
                );
            }
        }
    }

    fn hidden() -> HiddenWorld {
        HiddenWorld {
            worktree_roots: vec!["/srv/checkouts/w1".into()],
            user_homes: vec!["/home/devhome".into()],
            staging_roots: vec!["/var/rabs/staging/attempt-8f2c".into()],
            identities: vec!["build-user-9".into(), "buildhost-42".into()],
            secret_backing_roots: vec!["/var/rabs/secret-backing".into()],
        }
    }

    #[test]
    fn seeded_leaks_of_every_class_are_caught() {
        // THE acceptance: one seeded leak per class.
        let cases: Vec<(Surface, &[u8], LeakClass, bool)> = vec![
            (
                Surface::LoadableArtifact,
                b"embedded: /srv/checkouts/w1/src/lib.rs",
                LeakClass::OutputSemanticPathSensitivity,
                true,
            ),
            (
                Surface::DebugMetadata,
                b"DW_AT_comp_dir /srv/checkouts/w1",
                LeakClass::RemappableDebugMetadata,
                true,
            ),
            (
                Surface::DepInfo,
                b"t: /var/rabs/staging/attempt-8f2c/src.rs",
                LeakClass::KeyRelevantSemanticLeakage,
                true,
            ),
            (
                Surface::PresentationTranscript,
                b"error at /srv/checkouts/w1/src/lib.rs:3",
                LeakClass::PresentationOnlyTranslated,
                true,
            ),
            (
                Surface::GeneratedSource,
                b"const P: &str = \"/home/devhome\";",
                LeakClass::KeyRelevantSemanticLeakage,
                true,
            ),
            (
                Surface::LoadableArtifact,
                b"/var/rabs/secret-backing/slot1",
                LeakClass::PrivacySecretIncident,
                true,
            ),
            (
                Surface::CargoMetadataHash,
                b"-Cmetadata=abc123",
                LeakClass::NonCanonicalLaunchEvidence,
                false, // canonical launch NOT verified
            ),
        ];
        for (surface, bytes, expected, canonical) in cases {
            let findings = scan_surface(surface, bytes, &hidden(), canonical);
            assert!(
                findings.iter().any(|f| f.class == expected),
                "{surface:?}: expected {expected:?}, got {findings:?}"
            );
        }
        // Clean canonical bytes on every surface: no findings.
        for surface in [
            Surface::LoadableArtifact,
            Surface::DebugMetadata,
            Surface::DepInfo,
        ] {
            assert!(
                scan_surface(surface, b"/__rabs/workspace/src/lib.rs", &hidden(), true).is_empty()
            );
        }
    }

    #[test]
    fn ambiguous_loadable_leakage_loses_portable_authority() {
        // THE routing rule: loadable/key-relevant leakage -> the
        // path-preserving lane, never a canonical hit.
        let loadable = scan_surface(
            Surface::LoadableArtifact,
            b"/srv/checkouts/w1/data",
            &hidden(),
            true,
        );
        assert_eq!(disposition(&loadable), ScanDisposition::PathPreservingLane);
        // Debug-only: remap then share.
        let debug = scan_surface(
            Surface::DebugMetadata,
            b"/srv/checkouts/w1",
            &hidden(),
            true,
        );
        assert_eq!(disposition(&debug), ScanDisposition::RemapThenShare);
        // Presentation-only: canonical authority holds.
        let transcript = scan_surface(
            Surface::PresentationTranscript,
            b"/srv/checkouts/w1/src/lib.rs:3",
            &hidden(),
            true,
        );
        assert_eq!(
            disposition(&transcript),
            ScanDisposition::CanonicalAuthorityHolds
        );
        // Secrets: incident dominates everything.
        let mixed = [
            scan_surface(
                Surface::DebugMetadata,
                b"/srv/checkouts/w1",
                &hidden(),
                true,
            ),
            scan_surface(
                Surface::LoadableArtifact,
                b"/var/rabs/secret-backing/slot1",
                &hidden(),
                true,
            ),
        ]
        .concat();
        assert_eq!(disposition(&mixed), ScanDisposition::Incident);
    }

    #[test]
    fn username_leaks_classify_by_surface() {
        // A username in loadable bytes is privacy; in debug metadata
        // it is remappable; in a transcript it is presentation.
        let loadable = scan_surface(
            Surface::LoadableArtifact,
            b"user=build-user-9",
            &hidden(),
            true,
        );
        assert!(
            loadable
                .iter()
                .any(|f| f.class == LeakClass::PrivacySecretIncident)
        );
        let debug = scan_surface(
            Surface::DebugMetadata,
            b"built by build-user-9",
            &hidden(),
            true,
        );
        assert!(
            debug
                .iter()
                .any(|f| f.class == LeakClass::RemappableDebugMetadata)
        );
    }
}
