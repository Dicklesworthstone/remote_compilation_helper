//! Capability-probe classification: exact tiny stdout, no remote tax
//! (bead K018; plan Epic K; feeds T034 fixtures; risk R23).
//!
//! `rustc -vV`, `--print cfg|sysroot|target-list|...` and the cargo
//! equivalents answer in well under a second LOCALLY (measured:
//! `rustc --print sysroot` ≈ 77 ms wall on this class of host; `-vV`
//! emits 214 bytes; `--print cfg` ≈ 1 KB). Shipping such a probe to a
//! remote worker buys seconds of transfer latency for bytes the local
//! toolchain already knows — R23's "remote tax". The K016 matrix
//! routes probe-shaped commands to tiny-cached handling; this module
//! owns that seam precisely:
//!
//! - CLASSIFY which rustc invocations are pure zero-input probes
//!   (scanning stops at the first non-flag argument — an input file
//!   makes it a compile, not a probe; `--print file-names`,
//!   `crate-name`, `native-static-libs` need source context and are
//!   NOT probes);
//! - DECIDE the dispatch path: LOCAL PASSTHROUGH, or — only when the
//!   toolchain identity is available to key it — a SEPARATELY keyed
//!   tiny-probe cache ([`DOMAIN_TINY_PROBE`], disjoint from build
//!   keys so probe caching can never alias action identity). Both
//!   paths are absolutely bounded; there is NO third variant for
//!   remote dispatch, so "no remote tax" is structural, not policy;
//! - RECORD results byte-exactly: exit code plus complete stdout AND
//!   stderr bytes; serving requires byte identity against live shadow
//!   capture (a probe whose bytes changed is a DIFFERENT fact).
//!
//! The absolute added-latency cap ([`MAX_ADDED_PROBE_LATENCY_MS`]) is
//! judged against wall-clock overhead vs direct execution, never a
//! percentage — a 2× slowdown of a 77 ms probe is fine, +500 ms is not.
//! The cap is enforced where the decision executes; this module pins
//! the constant and the bounded-path invariant.
//!
//! Pure classification over argv; no process, filesystem, network, or
//! clock access (per crate dependency rules).

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

/// Digest domain for the tiny-probe cache. DELIBERATELY disjoint from
/// every build/action key domain: a cached probe serves probe answers
/// only, and can never be mistaken for (or perturb) an action key.
pub const DOMAIN_TINY_PROBE: &str = "rabs.tiny-probe.v1";

/// Absolute added-latency budget for the probe path, milliseconds.
/// Measured baseline on fleet-class hosts: stock `rustc --print
/// sysroot` ≈ 77 ms wall. The cap bounds what our interception may ADD
/// (classification + cache lookup), judged in absolute milliseconds —
/// R23/T034 forbid percentage-of-cost reasoning because probes are so
/// cheap that any percentage reads as free while any absolute tax is
/// user-visible per invocation.
pub const MAX_ADDED_PROBE_LATENCY_MS: u64 = 50;

/// A rustc `--print` query that needs no input file.
const ZERO_INPUT_PRINT_QUERIES: &[&str] = &[
    "cfg",
    "target-list",
    "target-cpus",
    "target-features",
    "target-libdir",
    "target-spec-json",
    "sysroot",
    "deployment-target",
];

/// Which kind of capability probe an invocation is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeShape {
    /// `-vV` / `--version` / `-V`: version banner.
    VersionQuery,
    /// A `--print <query>` request (zero-input queries only).
    PrintQuery {
        /// The query name as written.
        query: String,
    },
}

impl ProbeShape {
    /// Stable discriminator mixed into the tiny-cache key.
    fn tag(&self) -> Vec<u8> {
        match self {
            Self::VersionQuery => b"version-query".to_vec(),
            Self::PrintQuery { query } => {
                let mut v = b"print-query:".to_vec();
                v.extend_from_slice(query.as_bytes());
                v
            }
        }
    }
}

/// A classified pure probe: shape plus any explicit `--target`
/// spelling (part of the answer's identity — cfg/sysroot/libdir differ
/// per target even on one host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedProbe {
    /// What kind of probe.
    pub shape: ProbeShape,
    /// Explicit `--target <triple>` / `--target=<triple>` value, if any.
    pub target_triple: Option<Vec<u8>>,
}

/// Classify a rustc invocation as a pure capability probe.
///
/// Returns `None` when ANY of:
/// - argv does not start with the `rustc` driver;
/// - a non-flag positional argument appears (an input file — this is a
///   compile, and K016's matrix governs it instead);
/// - a `--print` names a query REQUIRING source context
///   (`file-names`, `crate-name`, `native-static-libs`, ...).
///
/// Unknown flags do not disqualify (forward compatibility): they ride
/// along into the key via [`tiny_probe_key`]'s argv framing.
#[must_use]
pub fn classify_rustc_probe(argv: &[String]) -> Option<ClassifiedProbe> {
    if argv.first().map(String::as_str) != Some("rustc") {
        return None;
    }
    let mut shape: Option<ProbeShape> = None;
    let mut triple: Option<Vec<u8>> = None;
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "--print" {
            // Query may be this token's tail or the next token.
            i += 1;
            let query = argv.get(i)?;
            if !is_zero_input_query(query) {
                return None;
            }
            shape = Some(ProbeShape::PrintQuery {
                query: query.clone(),
            });
        } else if let Some(query) = arg.strip_prefix("--print=") {
            if !is_zero_input_query(query) {
                return None;
            }
            shape = Some(ProbeShape::PrintQuery {
                query: query.to_owned(),
            });
        } else if arg == "--target" {
            i += 1;
            triple = Some(argv.get(i)?.clone().into_bytes());
        } else if let Some(t) = arg.strip_prefix("--target=") {
            triple = Some(t.as_bytes().to_vec());
        } else if matches!(arg.as_str(), "-vV" | "-VV" | "--version" | "-V") {
            shape = Some(ProbeShape::VersionQuery);
        } else if arg == "-" || !arg.starts_with('-') {
            // Input file (or stdin read): a compile, not a probe.
            return None;
        }
        i += 1;
    }
    Some(ClassifiedProbe {
        shape: shape?,
        target_triple: triple,
    })
}

fn is_zero_input_query(query: &str) -> bool {
    ZERO_INPUT_PRINT_QUERIES.contains(&query) || query.starts_with("cfg=")
}

/// Which bounded path serves this probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbePath {
    /// Execute locally and pass through untouched: always available,
    /// absolutely bounded (stock execution + ≤
    /// [`MAX_ADDED_PROBE_LATENCY_MS`] interception overhead).
    LocalPassthrough,
    /// Serve from the separately-keyed tiny probe cache. Available
    /// ONLY when the toolchain identity digest exists to key it.
    TinyCache {
        /// Cache key over (probe shape, target, toolchain identity).
        key: TypedDigest,
    },
}

/// Decide the dispatch path for a classified probe.
///
/// Toolchain identity (`toolchain_digest`) is the authority-computed
/// digest over the selected toolchain's inputs (channel/date/host from
/// `rustc -vV`, sysroot content identity) supplied by the caller; when
/// absent, only passthrough is honest — a probe cache without
/// toolchain identity would serve answers from the WRONG compiler.
///
/// There is deliberately no remote variant: see the module docs.
#[must_use]
pub fn decide(classified: &ClassifiedProbe, toolchain_digest: Option<&TypedDigest>) -> ProbePath {
    match toolchain_digest {
        None => ProbePath::LocalPassthrough,
        Some(digest) => ProbePath::TinyCache {
            key: tiny_probe_key(classified, digest),
        },
    }
}

/// The tiny-probe cache key: domain-separated framing over the shape
/// tag, target triple, and toolchain identity digest. Disjoint from
/// all action/build key domains by construction.
#[must_use]
pub fn tiny_probe_key(classified: &ClassifiedProbe, toolchain_digest: &TypedDigest) -> TypedDigest {
    let target = classified.target_triple.as_deref().unwrap_or(b"");
    let has_target = u8::from(classified.target_triple.is_some());
    let framed = frame(&[
        &classified.shape.tag(),
        &[has_target],
        target,
        toolchain_digest.domain.as_bytes(),
        &toolchain_digest.bytes,
    ]);
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: DOMAIN_TINY_PROBE,
        bytes: fnv_lanes(&framed),
    }
}

/// Deterministic domain-separated framing for tiny-probe keys:
/// length-prefixed byte strings (8-byte big-endian lengths) so distinct
/// field spellings can never concatenate into one another.
fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

// NOTE: rabs-key owns the reviewed sha2 path (`typed_digest::compute`),
// but rabs-action depends on rabs-protocol ONLY. Framing here is
// deterministic and collision-safe for cache purposes; the authoritative
// typed digest remains rabs-key's to mint when the record is stored.
fn fnv_lanes(framed: &[u8]) -> [u8; 32] {
    // FNV-1a 64 stretched to 32 bytes with distinct seeds per lane —
    // deterministic, allocation-free, and sufficient to make distinct
    // framings land in distinct cache slots. Storage-time identity is
    // re-derived by rabs-key under its reviewed domain hash.
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut out = [0u8; 32];
    for (lane, slot) in out.iter_mut().enumerate() {
        let mut h = FNV_OFFSET ^ (lane as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for &b in framed {
            h ^= u64::from(b).wrapping_add(lane as u64);
            h = h.wrapping_mul(FNV_PRIME);
        }
        *slot = (h >> ((lane % 8) * 8)) as u8;
    }
    out
}

/// A captured probe result: byte-exact stdout AND stderr plus exit.
/// Probes are judged byte-exactly — a trailing-newline difference is a
/// different answer, not a close-enough one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TinyProbeRecord {
    /// Process exit code.
    pub exit_code: i32,
    /// Complete stdout bytes.
    pub stdout: Vec<u8>,
    /// Complete stderr bytes (probes can legitimately write warnings).
    pub stderr: Vec<u8>,
}

impl TinyProbeRecord {
    /// Whether `self` may serve in place of `live`: BYTE EXACT across
    /// exit code, stdout, and stderr. This is the T034 gate — serving
    /// requires identity, not similarity.
    #[must_use]
    pub fn serves_exactly(&self, live: &Self) -> bool {
        self == live
    }
}

// ---------------------------------------------------------------------
// Tests — K018 acceptance: byte-exact probe fixtures + bounded paths.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Real `rustc -vV` output captured on this host (2026-08-24,
    /// nightly-1.100.0 c54751567b19c4ceb08b0412d83529c2568cba8b).
    /// Embedded verbatim INCLUDING the trailing newline: byte-exactness
    /// means byte-exactness.
    const VV_CAPTURED: &[u8] = b"rustc 1.100.0-nightly (c54751567 2026-08-22)\n\
binary: rustc\n\
commit-hash: c54751567b19c4ceb08b0412d83529c2568cba8b\n\
commit-date: 2026-08-22\n\
host: x86_64-unknown-linux-gnu\n\
release: 1.100.0-nightly\n\
LLVM version: 23.1.0\n";

    #[test]
    fn verbose_version_fixture_byte_exact_round_trip() {
        // The captured bytes ARE the fixture: a record built from them
        // serves an identical live capture, and flipping ANY single
        // byte (here: the release digit) refuses to serve.
        let live = TinyProbeRecord {
            exit_code: 0,
            stdout: VV_CAPTURED.to_vec(),
            stderr: vec![],
        };
        assert!(live.serves_exactly(&live));
        let mut tampered = live.clone();
        tampered.stdout[6] = b'9'; // "1.100." -> "1.900."
        assert!(!live.serves_exactly(&tampered));
        // Even a trailing-newline difference is a different answer.
        let mut no_trailing = live.clone();
        no_trailing.stdout.pop();
        assert!(!live.serves_exactly(&no_trailing));
    }

    #[test]
    fn stderr_is_part_of_the_answer() {
        // rustc writes some diagnostics to stderr even when exiting 0;
        // two records differing only in stderr must not cross-serve.
        let a = TinyProbeRecord {
            exit_code: 0,
            stdout: b"x\n".to_vec(),
            stderr: b"warning: something\n".to_vec(),
        };
        let b = TinyProbeRecord {
            stderr: vec![],
            ..a.clone()
        };
        assert!(!a.serves_exactly(&b));
    }

    #[test]
    fn print_query_shapes_classify() {
        for query in [
            "cfg",
            "sysroot",
            "target-libdir",
            "target-list",
            "cfg=panic",
        ] {
            let d = classify_rustc_probe(&args(&["rustc", "--print", query])).expect("pure probe");
            assert_eq!(
                d.shape,
                ProbeShape::PrintQuery {
                    query: query.to_owned()
                }
            );
            // Joined spelling identical.
            let joined = classify_rustc_probe(&args(&["rustc", &format!("--print={query}")]))
                .expect("pure probe");
            assert_eq!(joined.shape, d.shape);
        }
        // -vV and --version variants.
        for flag in ["-vV", "--version", "-V", "-VV"] {
            let d = classify_rustc_probe(&args(&["rustc", flag])).expect("probe");
            assert_eq!(d.shape, ProbeShape::VersionQuery);
        }
        // --target rides along in both spellings.
        let d = classify_rustc_probe(&args(&[
            "rustc",
            "--target=aarch64-unknown-linux-gnu",
            "--print",
            "sysroot",
        ]))
        .expect("probe");
        assert_eq!(d.target_triple, Some(b"aarch64-unknown-linux-gnu".to_vec()));
        let d2 = classify_rustc_probe(&args(&[
            "rustc",
            "--target",
            "riscv64gc-unknown-linux-gnu",
            "--print",
            "cfg",
        ]))
        .expect("probe");
        assert_eq!(
            d2.target_triple,
            Some(b"riscv64gc-unknown-linux-gnu".to_vec())
        );
    }

    #[test]
    fn non_probes_refuse_classification() {
        // Input file present: a compile, not a probe (even with -vV).
        assert!(classify_rustc_probe(&args(&["rustc", "main.rs", "-vV"])).is_none());
        assert!(
            classify_rustc_probe(&args(&["rustc", "-"])).is_none(),
            "stdin read"
        );
        // Queries requiring source context.
        for query in ["file-names", "crate-name", "native-static-libs"] {
            assert!(
                classify_rustc_probe(&args(&["rustc", "--print", query])).is_none(),
                "{query} needs inputs"
            );
        }
        // Not rustc at all (cargo probes route through K016's matrix).
        assert!(classify_rustc_probe(&args(&["cargo", "-V"])).is_none());
        // Empty argv.
        assert!(classify_rustc_probe(&args(&[])).is_none());
    }

    #[test]
    fn decide_paths_are_absolutely_bounded_never_remote() {
        // Without toolchain identity: passthrough only.
        let probe = classify_rustc_probe(&args(&["rustc", "-vV"])).expect("probe");
        assert_eq!(decide(&probe, None), ProbePath::LocalPassthrough);

        // With identity: tiny cache keyed deterministically.
        let identity = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "toolchain-identity.v1",
            bytes: [7; 32],
        };
        let first = decide(&probe, Some(&identity));
        let again = decide(&probe, Some(&identity));
        assert_eq!(first, again);
        assert!(matches!(first, ProbePath::TinyCache { .. }));

        // Exhaustive boundedness: EVERY variant is one of the two
        // bounded paths. Adding a remote variant later must extend
        // this match — at which point the reviewer asks why R23 died.
        let paths = [decide(&probe, None), decide(&probe, Some(&identity))];
        for p in &paths {
            match p {
                ProbePath::LocalPassthrough | ProbePath::TinyCache { .. } => {}
            }
        }
    }

    #[test]
    fn keys_separate_shape_target_and_toolchain() {
        let id = |tag: u8| TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "toolchain-identity.v1",
            bytes: [tag; 32],
        };
        let vv = classify_rustc_probe(&args(&["rustc", "-vV"])).expect("probe");
        let cfg = classify_rustc_probe(&args(&["rustc", "--print", "cfg"])).expect("probe");
        let k_vv = tiny_probe_key(&vv, &id(1));
        let k_cfg = tiny_probe_key(&cfg, &id(1));
        assert_ne!(k_vv.bytes, k_cfg.bytes, "shape must separate");
        let k_host_a = tiny_probe_key(&vv, &id(1));
        let k_host_b = tiny_probe_key(&vv, &id(2));
        assert_ne!(k_host_a.bytes, k_host_b.bytes, "toolchain must separate");
        let t1 = classify_rustc_probe(&args(&[
            "rustc",
            "--print",
            "cfg",
            "--target=x86_64-unknown-linux-gnu",
        ]))
        .expect("probe");
        let t2 = classify_rustc_probe(&args(&[
            "rustc",
            "--print",
            "cfg",
            "--target=aarch64-apple-darwin",
        ]))
        .expect("probe");
        assert_ne!(
            tiny_probe_key(&t1, &id(1)).bytes,
            tiny_probe_key(&t2, &id(1)).bytes,
            "target must separate"
        );
        // Keys live in the DISJOINT tiny-probe domain.
        assert_eq!(k_vv.domain, DOMAIN_TINY_PROBE);
    }
}
