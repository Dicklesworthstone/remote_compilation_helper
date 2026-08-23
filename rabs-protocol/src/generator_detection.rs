//! Volatile-generator pattern detection for build scripts (bead N006;
//! plan §196 Epic N; feeds volatility classification consumed by the
//! N005 policy split).
//!
//! Build scripts commonly embed VOLATILE facts — build timestamps, git
//! state, network-fetched data — through well-known generator crates or
//! hand-rolled shell-outs. A run cache that ignores these serves stale
//! `NOW`, stale `HEAD`, stale downloads. Detection scans the build
//! script SOURCE (bytes, line-oriented) against a CLOSED V1 registry of
//! patterns and reports every hit with its byte-exact evidence line:
//!
//! - [`GeneratorPattern::Vergen`] / [`GeneratorPattern::Built`] —
//!   generator crates whose whole purpose is embedding build-time facts;
//! - [`GeneratorPattern::TimestampEmbedding`] — direct clock reads
//!   (`SystemTime::now()`, `chrono::Utc::now()`,
//!   `time::OffsetDateTime`);
//! - [`GeneratorPattern::GitDescribe`] — git state probes (`git
//!   describe`/`rev-parse` shells, `.git/HEAD` reads);
//! - [`GeneratorPattern::NetworkFetch`] — outbound fetchers (`reqwest`,
//!   `ureq`, `TcpStream::connect`, `curl`/`wget` invocations).
//!
//! Classification is CONSERVATIVE in one direction only: any detection
//! makes the script [`Volatility::Volatile`] with per-pattern reason
//! codes; a clean scan yields [`Volatility::Stable`]. Unknown generators
//! are undetectable by construction — that residual risk is N005's
//! audit-first posture, not a claim this registry cannot be bypassed.
//!
//! Zero deps, pure bytes, deterministic.

/// The closed V1 registry of volatile-generator patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // Registry names are ecosystem vocabulary.
pub enum GeneratorPattern {
    Vergen,
    Built,
    TimestampEmbedding,
    GitDescribe,
    NetworkFetch,
}

impl GeneratorPattern {
    /// Stable reason code fed into volatility classification and
    /// actionable `rch why` refusals.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Vergen => "volatile-generator-vergen",
            Self::Built => "volatile-generator-built",
            Self::TimestampEmbedding => "volatile-clock-read",
            Self::GitDescribe => "volatile-git-state",
            Self::NetworkFetch => "volatile-network-fetch",
        }
    }

    /// Byte tokens whose presence in ONE line signals this pattern.
    fn tokens(self) -> &'static [&'static [u8]] {
        match self {
            Self::Vergen => &[b"vergen::", b"vergen_emit", b"Emitter::default()"],
            Self::Built => &[b"built::"],
            Self::TimestampEmbedding => &[
                b"SystemTime::now()",
                b"chrono::Utc::now()",
                b"time::OffsetDateTime",
                b"time::Instant::now()",
            ],
            Self::GitDescribe => &[
                b"git describe",
                b"git rev-parse",
                b".git/HEAD",
                b"Command::new(\"git\")",
            ],
            Self::NetworkFetch => &[
                b"reqwest::",
                b"ureq::",
                b"TcpStream::connect",
                b"curl ",
                b"wget ",
            ],
        }
    }
}

const ALL_PATTERNS: [GeneratorPattern; 5] = [
    GeneratorPattern::Vergen,
    GeneratorPattern::Built,
    GeneratorPattern::TimestampEmbedding,
    GeneratorPattern::GitDescribe,
    GeneratorPattern::NetworkFetch,
];

/// One detected occurrence: pattern + 1-based source line of the FIRST
/// match + total matching lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Which pattern fired.
    pub pattern: GeneratorPattern,
    /// 1-based line number of the first matching line.
    pub first_line: usize,
    /// Total number of matching lines.
    pub match_count: usize,
}

/// Volatility classification of a scanned build script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Volatility {
    /// No registered pattern detected. NOT a proof of determinism —
    /// unknown generators exist (N005 audits anyway).
    Stable,
    /// At least one volatile generator detected; reasons carry the
    /// stable reason codes for refusals.
    Volatile {
        /// One reason code per detected pattern (deduped, registry
        /// order).
        reasons: Vec<&'static str>,
    },
}

/// Scan build-script source bytes for every registry pattern.
///
/// Line-oriented: lines split on `\n`; matches are case-sensitive
/// byte-token searches (generator APIs are spelled exactly). Patterns
/// dedupe per-pattern: a script hitting `vergen::` five times yields
/// ONE detection with count five.
#[must_use]
pub fn detect_generators(source: &[u8]) -> Vec<Detection> {
    let mut detections = Vec::new();
    for pattern in ALL_PATTERNS {
        let mut first_line: Option<usize> = None;
        let mut count = 0usize;
        for (idx, line) in source.split(|&b| b == b'\n').enumerate() {
            if contains(line, pattern) {
                count += 1;
                if first_line.is_none() {
                    first_line = Some(idx + 1);
                }
            }
        }
        if let Some(line_no) = first_line {
            detections.push(Detection {
                pattern,
                first_line: line_no,
                match_count: count,
            });
        }
    }
    detections
}

fn contains(haystack: &[u8], pattern: GeneratorPattern) -> bool {
    pattern
        .tokens()
        .iter()
        .any(|t| haystack.windows(t.len()).any(|w| w == *t))
}

/// Classify volatility from detections: ANY detection ⇒ Volatile with
/// that pattern's reason code; empty ⇒ Stable.
#[must_use]
pub fn classify_volatility(detections: &[Detection]) -> Volatility {
    if detections.is_empty() {
        return Volatility::Stable;
    }
    let mut reasons = Vec::new();
    for pattern in ALL_PATTERNS {
        if detections.iter().any(|d| d.pattern == pattern) {
            reasons.push(pattern.reason_code());
        }
    }
    Volatility::Volatile { reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns_of(ds: &[Detection]) -> Vec<GeneratorPattern> {
        ds.iter().map(|d| d.pattern).collect()
    }

    /// Each registry pattern fires on its own fixture shape.
    #[test]
    fn n006_detection_fixtures_for_each_pattern() {
        assert_eq!(
            patterns_of(&detect_generators(
                b"use vergen::EmitBuilder;\nlet e = EmitBuilder::default();\n"
            )),
            vec![GeneratorPattern::Vergen]
        );
        assert_eq!(
            patterns_of(&detect_generators(b"let info = built::util::str_list();\n")),
            vec![GeneratorPattern::Built]
        );
        assert_eq!(
            patterns_of(&detect_generators(
                b"let now = std::time::SystemTime::now();\n"
            )),
            vec![GeneratorPattern::TimestampEmbedding]
        );
        assert_eq!(
            patterns_of(&detect_generators(
                b"let tag = Command::new(\"git\").args([\"describe\"]);\n"
            )),
            vec![GeneratorPattern::GitDescribe]
        );
        assert_eq!(
            patterns_of(&detect_generators(
                b"let body = reqwest::blocking::get(url)?;\n"
            )),
            vec![GeneratorPattern::NetworkFetch]
        );
    }

    /// Volatility classification feeds the policy layer with stable
    /// reason codes, deduped in registry order.
    #[test]
    fn n006_volatility_classification_carries_deduped_reasons() {
        let ds = detect_generators(
            b"let t = SystemTime::now();\n\
              let u = SystemTime::now();\n\
              let g = built::info();\n",
        );
        // TimestampEmbedding x2 collapses to one detection.
        assert_eq!(
            patterns_of(&ds),
            vec![
                GeneratorPattern::Built,
                GeneratorPattern::TimestampEmbedding,
            ]
        );
        match classify_volatility(&ds) {
            Volatility::Volatile { reasons } => {
                assert_eq!(
                    reasons,
                    vec!["volatile-generator-built", "volatile-clock-read"]
                );
            }
            other => panic!("expected volatile, got {other:?}"),
        }
    }

    /// Clean scripts classify Stable — registry-scoped honesty note
    /// applies (unknown generators are N005's audit problem).
    #[test]
    fn n006_clean_script_is_stable() {
        let src = b"fs::write(out.join(\"gen.rs\"), \"x\")?;\n\
                    println!(\"cargo:rerun-if-changed=build.rs\");\n";
        assert!(detect_generators(src).is_empty());
        assert_eq!(classify_volatility(&[]), Volatility::Stable);
        assert_eq!(
            classify_volatility(&detect_generators(src)),
            Volatility::Stable
        );
    }

    /// First-line reporting is 1-based and counts occurrences.
    #[test]
    fn n006_first_line_and_counts_are_accurate() {
        let ds = detect_generators(
            b"// nothing\n\
              // still nothing\n\
              let u = ureq::get(\"https://x\");\n\
              // noise\n\
              let v = ureq::post(\"https://y\");\n",
        );
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].pattern, GeneratorPattern::NetworkFetch);
        assert_eq!(ds[0].first_line, 3);
        assert_eq!(ds[0].match_count, 2);
    }

    /// Multi-generator scripts accumulate all patterns; ordering follows
    /// the registry, not the source layout.
    #[test]
    fn n006_multi_pattern_scripts_report_every_hit() {
        let ds = detect_generators(
            b"vergen::emit();\n\
              SystemTime::now();\n\
              ureq::get(u);\n\
              git describe --dirty;\n\
              built::info();\n",
        );
        assert_eq!(
            patterns_of(&ds),
            vec![
                GeneratorPattern::Vergen,
                GeneratorPattern::Built,
                GeneratorPattern::TimestampEmbedding,
                GeneratorPattern::GitDescribe,
                GeneratorPattern::NetworkFetch,
            ]
        );
        match classify_volatility(&ds) {
            Volatility::Volatile { reasons } => assert_eq!(reasons.len(), 5),
            other => panic!("expected volatile, got {other:?}"),
        }
    }
}
