//! Doctest compile/run actions (bead O010; plan §102).
//!
//! Doctests are extracted by rustdoc into GENERATED crates whose
//! source identity is what a doctest action keys on:
//!
//! - `DoctestCompile` and `DoctestRun` are separate cacheable classes
//!   (the E001 registry rows exist; this module supplies the keyed
//!   identity of the generated crate);
//! - the generated crate's identity CANONICALIZES: the extracted
//!   snippet bytes, the source location (file + line — part of the
//!   snippet's compiled identity via the doctest preamble), the
//!   surrounding crate's rmeta, and the extraction-tool identity —
//!   NOT rustdoc's temp-dir spelling or generated file names;
//! - the identity is EXPLAINABLE: the breakdown names each component
//!   so `rch why` can attribute a doctest miss;
//! - profile policy: an agent inner loop may EXCLUDE doctests by
//!   profile; CI runs canonical coverage — the exclusion is a
//!   profile fact, never a silent skip.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for generated-doctest identity.
pub const DOMAIN_DOCTEST_IDENTITY: &str = "rabs.doctest-identity.v1";

/// One extracted doctest's canonical identity inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctestIdentity {
    /// The extracted snippet's exact bytes.
    pub snippet: Vec<u8>,
    /// Virtual source file the snippet came from.
    pub source_file: String,
    /// Line the snippet starts at (part of the compiled preamble).
    pub line: u32,
    /// The surrounding crate's rmeta digest (doctests link against it).
    pub host_crate_rmeta: TypedDigest,
    /// The extraction tool's identity (rustdoc, via F007).
    pub extractor_identity: TypedDigest,
}

impl DoctestIdentity {
    /// The canonical identity digest with its explainable breakdown.
    #[must_use]
    pub fn identity(&self) -> (TypedDigest, Vec<(&'static str, String)>) {
        let mut enc = CanonicalEncoder::new();
        enc.bytes(&self.snippet)
            .str(&self.source_file)
            .u32(self.line)
            .str(self.host_crate_rmeta.domain)
            .bytes(&self.host_crate_rmeta.bytes)
            .str(self.extractor_identity.domain)
            .bytes(&self.extractor_identity.bytes);
        let digest = compute(DOMAIN_DOCTEST_IDENTITY, &enc.finish());
        let breakdown = vec![
            ("snippet-bytes", format!("{} bytes", self.snippet.len())),
            (
                "source-location",
                format!("{}:{}", self.source_file, self.line),
            ),
            ("host-crate-rmeta", self.host_crate_rmeta.domain.to_owned()),
            ("extractor", self.extractor_identity.domain.to_owned()),
        ];
        (digest, breakdown)
    }
}

/// Doctest profile policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctestPolicy {
    /// Doctests excluded BY PROFILE (agent inner loop) — an explicit
    /// recorded fact, never a silent skip.
    ExcludedByProfile,
    /// Canonical coverage (CI): doctests compile and run.
    CanonicalCoverage,
}

/// Decide the doctest policy from the profile.
#[must_use]
pub fn doctest_policy(profile_excludes_doctests: bool) -> DoctestPolicy {
    if profile_excludes_doctests {
        DoctestPolicy::ExcludedByProfile
    } else {
        DoctestPolicy::CanonicalCoverage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::descriptor::ActionClass;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn identity() -> DoctestIdentity {
        DoctestIdentity {
            snippet: b"assert_eq!(parse(\"1\"), Ok(1));".to_vec(),
            source_file: "/__rabs/workspace/src/lib.rs".into(),
            line: 42,
            host_crate_rmeta: d(1),
            extractor_identity: d(2),
        }
    }

    #[test]
    fn doctest_classes_are_separate_and_cacheable() {
        // THE class fixtures: DoctestCompile and DoctestRun exist as
        // distinct classes with distinct E001 policies (both
        // registered; the registry rows govern cacheability).
        use rabs_protocol::class_policy::policy_for;
        let compile = policy_for(ActionClass::DoctestCompile);
        let run = policy_for(ActionClass::DoctestRun);
        assert_ne!(compile.class, run.class);
        assert!(compile.local_cache && run.local_cache);
    }

    #[test]
    fn generated_identity_canonicalizes_without_temp_spellings() {
        // THE canonicalization acceptance: the identity has NO field
        // for rustdoc's temp dir or generated file names — two
        // extractions of one snippet are one identity by construction.
        let (a, _) = identity().identity();
        let (b, _) = identity().identity();
        assert_eq!(a, b);
        let DoctestIdentity {
            snippet: _,
            source_file: _,
            line: _,
            host_crate_rmeta: _,
            extractor_identity: _,
        } = identity(); // no temp-path field exists
        // Every real component forks the identity.
        let mut m = identity();
        m.snippet = b"changed".to_vec();
        assert_ne!(a, m.identity().0);
        let mut m = identity();
        m.line = 43; // line is part of the compiled preamble
        assert_ne!(a, m.identity().0);
        let mut m = identity();
        m.host_crate_rmeta = d(9);
        assert_ne!(a, m.identity().0, "host crate change invalidates");
        let mut m = identity();
        m.extractor_identity = d(9);
        assert_ne!(a, m.identity().0, "rustdoc change invalidates");
    }

    #[test]
    fn the_identity_is_explainable() {
        let (_, breakdown) = identity().identity();
        let names: Vec<&str> = breakdown.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "snippet-bytes",
                "source-location",
                "host-crate-rmeta",
                "extractor"
            ],
            "rch why can attribute a doctest miss by component"
        );
        assert!(breakdown[1].1.ends_with(":42"));
    }

    #[test]
    fn exclusion_is_a_profile_fact_never_a_silent_skip() {
        assert_eq!(
            doctest_policy(true),
            DoctestPolicy::ExcludedByProfile,
            "the agent inner loop excludes EXPLICITLY"
        );
        assert_eq!(doctest_policy(false), DoctestPolicy::CanonicalCoverage);
        // Both outcomes are explicit variants: silence is not a state.
        match doctest_policy(true) {
            DoctestPolicy::ExcludedByProfile | DoctestPolicy::CanonicalCoverage => {}
        }
    }
}
