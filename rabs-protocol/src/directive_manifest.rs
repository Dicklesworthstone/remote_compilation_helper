//! Structured Cargo-directive manifest over captured build-script
//! streams (bead N002; plan §196 Epic N; rides the C007/K006 stream
//! machinery in [`crate::stream_chunker`]).
//!
//! Cargo consumes `cargo:*` lines from a build script's STDOUT only;
//! stderr is human diagnostics. The manifest therefore has ONE
//! well-defined order — stdout arrival order — and records each
//! directive's position in the SHARED cross-stream sequence
//! ([`crate::stream_chunker::CanonicalObservation`] `seq`) instead of
//! inventing an unknowable total order between independently piped
//! streams:
//!
//! - **Exactness**: every directive keeps its RAW captured line bytes,
//!   terminator included, alongside the parsed key/value split; the
//!   parsed form never replaces the bytes, it annotates them.
//! - **Faithful unknowns**: a directive key outside the closed V1
//!   registry is captured as [`DirectiveKind::Unknown`] with its exact
//!   bytes intact — capture never refuses what was observed; policy
//!   layers (N014 validation, N005 release policy) decide later.
//! - **Loud spills**: an oversized stdout line is NOT parsable from
//!   resident memory; the manifest records it as an explicit
//!   [`ManifestEntry::UnparsedSpill`] rather than pretending the gap
//!   does not exist.
//! - **Zero deps, zero clocks**: ids, sequences, bytes, enums — same
//!   redaction-surface rules as every schema here.

use crate::stream_chunker::{CanonicalObservation, StdStream};

/// Schema version for the directive manifest.
pub const DIRECTIVE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Framing domain for the storage layer's digest over
/// [`DirectiveManifest::canonical_bytes`].
pub const DIRECTIVE_MANIFEST_FRAMING_DOMAIN: &str = "rabs.directive-manifest.sha256.v1";

/// Upper bound on manifest entries (bounded collections rule).
pub const MAX_MANIFEST_ENTRIES: usize = 8192;

/// The closed V1 registry of recognized Cargo directive kinds (spellings
/// exactly as Cargo defines them; case-sensitive matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // Registry names are cargo's own vocabulary.
pub enum DirectiveKind {
    RerunIfChanged,
    RerunIfEnvChanged,
    RustcEnv,
    RustcFlags,
    RustcLinkLib,
    RustcLinkSearch,
    RustcCdylibLinkArg,
    Warning,
    Metadata,
    DepInfo,
    /// Observed but outside the registry: bytes preserved verbatim,
    /// interpretation deferred to policy layers.
    Unknown,
}

impl DirectiveKind {
    /// The registry key spelling (what follows `cargo:` on the wire).
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::RerunIfChanged => "rerun-if-changed",
            Self::RerunIfEnvChanged => "rerun-if-env-changed",
            Self::RustcEnv => "rustc-env",
            Self::RustcFlags => "rustc-flags",
            Self::RustcLinkLib => "rustc-link-lib",
            Self::RustcLinkSearch => "rustc-link-search",
            Self::RustcCdylibLinkArg => "rustc-cdylib-link-arg",
            Self::Warning => "warning",
            Self::Metadata => "metadata",
            Self::DepInfo => "dep-info",
            Self::Unknown => "<unknown>",
        }
    }

    /// Map a captured key to its registry entry (exact bytes match only —
    /// cargo's own matching is case-sensitive).
    #[must_use]
    pub fn from_key(key: &[u8]) -> Self {
        match key {
            b"rerun-if-changed" => Self::RerunIfChanged,
            b"rerun-if-env-changed" => Self::RerunIfEnvChanged,
            b"rustc-env" => Self::RustcEnv,
            b"rustc-flags" => Self::RustcFlags,
            b"rustc-link-lib" => Self::RustcLinkLib,
            b"rustc-link-search" => Self::RustcLinkSearch,
            b"rustc-cdylib-link-arg" => Self::RustcCdylibLinkArg,
            b"warning" => Self::Warning,
            b"metadata" => Self::Metadata,
            b"dep-info" => Self::DepInfo,
            _ => Self::Unknown,
        }
    }
}

/// One structured entry of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestEntry {
    /// A parsed `cargo:` directive from stdout.
    Directive {
        /// Position in the SHARED arrival sequence (cross-stream); ties
        /// this row back to the exact captured observation.
        seq: u64,
        /// Registry classification (Unknown preserves foreign keys).
        kind: DirectiveKind,
        /// Exact captured key bytes (after `cargo:`, before `=`).
        key: Vec<u8>,
        /// Parsed value bytes: everything after the FIRST `=`, minus the
        /// line terminator. `None` for a key-only directive. Interior
        /// `=` bytes belong to the value, unsplit.
        value: Option<Vec<u8>>,
        /// The FULL captured line, terminator included — the parsed
        /// fields annotate these bytes, never replace them.
        raw_line: Vec<u8>,
    },
    /// An oversized stdout line: not parsable from resident memory, so
    /// recorded as a loud gap naming its spill object (N014 decides
    /// whether that blocks serving; capture does not hide it).
    UnparsedSpill {
        /// Shared arrival sequence.
        seq: u64,
        /// Spill object holding the original bytes.
        spill_id: u64,
        /// Total bytes of the original line (terminator included).
        total_bytes: u64,
    },
}

impl ManifestEntry {
    /// The shared-sequence position of any entry shape.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        match self {
            Self::Directive { seq, .. } | Self::UnparsedSpill { seq, .. } => *seq,
        }
    }
}

/// The structured directive manifest for one build-script run:
/// directives in stdout arrival order, each tied to the shared capture
/// sequence, exact bytes preserved beside the parsed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveManifest {
    /// Schema version ([`DIRECTIVE_MANIFEST_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Entries in ascending shared-sequence order.
    pub entries: Vec<ManifestEntry>,
}

/// Typed extraction refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestRefusal {
    /// Input observations were not in ascending shared-sequence order —
    /// the caller's transcript is corrupt; extraction refuses rather
    /// than silently reordering (anti-synthesis: we do not invent order).
    ObservationsOutOfOrder,
    /// More manifest entries than the bounded envelope allows.
    TooManyEntries,
}

/// Strip ONE trailing line terminator (`\r\n` or `\n`) from exact line
/// bytes; anything else returns the slice unchanged.
fn strip_terminator(line: &[u8]) -> &[u8] {
    if let Some(without_lf) = line.strip_suffix(b"\n") {
        if let Some(stripped) = without_lf.strip_suffix(b"\r") {
            return stripped;
        }
        return without_lf;
    }
    line
}

/// Extract the directive manifest from a captured observation
/// transcript, in arrival order.
///
/// # Errors
/// [`ManifestRefusal::ObservationsOutOfOrder`] when the transcript's
/// shared sequence regresses; [`ManifestRefusal::TooManyEntries`] when
/// the bounded envelope would overflow.
pub fn extract_directives(
    observations: &[CanonicalObservation],
) -> Result<DirectiveManifest, ManifestRefusal> {
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut last_seq: Option<u64> = None;
    for obs in observations {
        let seq = match obs {
            CanonicalObservation::Line { seq, .. }
            | CanonicalObservation::SpilledLine { seq, .. } => *seq,
            CanonicalObservation::TerminalExit { .. } => continue,
        };
        if last_seq.is_some_and(|prev| seq <= prev) {
            return Err(ManifestRefusal::ObservationsOutOfOrder);
        }
        last_seq = Some(seq);

        match obs {
            CanonicalObservation::Line {
                stream: StdStream::Stdout,
                seq,
                bytes,
            } => {
                if let Some(entry) = parse_directive(*seq, bytes) {
                    entries.push(entry);
                    if entries.len() > MAX_MANIFEST_ENTRIES {
                        return Err(ManifestRefusal::TooManyEntries);
                    }
                }
            }
            CanonicalObservation::SpilledLine {
                stream: StdStream::Stdout,
                seq,
                spill_id,
                total_bytes,
            } => {
                entries.push(ManifestEntry::UnparsedSpill {
                    seq: *seq,
                    spill_id: *spill_id,
                    total_bytes: *total_bytes,
                });
                if entries.len() > MAX_MANIFEST_ENTRIES {
                    return Err(ManifestRefusal::TooManyEntries);
                }
            }
            // stderr never carries directives; TerminalExit is not a
            // stream event. Nothing to record for either.
            CanonicalObservation::Line { .. }
            | CanonicalObservation::SpilledLine { .. }
            | CanonicalObservation::TerminalExit { .. } => {}
        }
    }
    Ok(DirectiveManifest {
        schema_version: DIRECTIVE_MANIFEST_SCHEMA_VERSION,
        entries,
    })
}

/// Parse ONE captured stdout line into a manifest entry, or `None` when
/// it is not a directive (non-`cargo:` output stays in the transcript
/// bytes; the manifest indexes structure, not chatter).
fn parse_directive(seq: u64, line: &[u8]) -> Option<ManifestEntry> {
    const PREFIX: &[u8] = b"cargo:";
    if line.len() < PREFIX.len() || &line[..PREFIX.len()] != PREFIX {
        return None;
    }
    let raw_line = line.to_vec();
    let body = strip_terminator(&line[PREFIX.len()..]);
    let (key, value) = match body.iter().position(|&b| b == b'=') {
        Some(eq) => (&body[..eq], Some(body[eq + 1..].to_vec())),
        None => (body, None),
    };
    Some(ManifestEntry::Directive {
        seq,
        kind: DirectiveKind::from_key(key),
        key: key.to_vec(),
        value,
        raw_line,
    })
}

impl DirectiveManifest {
    /// Whether any entry records an unparsed spill (a completeness gap
    /// policy layers must see).
    #[must_use]
    pub fn has_unparsed_spills(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e, ManifestEntry::UnparsedSpill { .. }))
    }

    /// All values recorded for one registry kind, in stdout order (the
    /// N004 DEP_LINKS reconstruction path reads [`DirectiveKind::Metadata`]
    /// rows this way).
    #[allow(clippy::must_use_candidate)] // Iterator is already must_use.
    pub fn values_of<'a>(&'a self, kind: DirectiveKind) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.entries.iter().filter_map(move |e| match e {
            ManifestEntry::Directive {
                kind: k,
                value: Some(v),
                ..
            } if *k == kind => Some(v.as_slice()),
            _ => None,
        })
    }

    /// The versioned, length-delimited byte projection of the manifest
    /// (little-endian lengths; fixed field order). Pure bytes: the
    /// STORAGE layer hashes under [`DIRECTIVE_MANIFEST_FRAMING_DOMAIN`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            match entry {
                ManifestEntry::Directive {
                    seq,
                    kind,
                    key,
                    value,
                    raw_line,
                } => {
                    out.push(1);
                    out.extend_from_slice(&seq.to_le_bytes());
                    out.push(kind_tag(*kind));
                    put_bytes(&mut out, key);
                    match value {
                        Some(v) => {
                            out.push(1);
                            put_bytes(&mut out, v);
                        }
                        None => out.push(0),
                    }
                    put_bytes(&mut out, raw_line);
                }
                ManifestEntry::UnparsedSpill {
                    seq,
                    spill_id,
                    total_bytes,
                } => {
                    out.push(2);
                    out.extend_from_slice(&seq.to_le_bytes());
                    out.extend_from_slice(&spill_id.to_le_bytes());
                    out.extend_from_slice(&total_bytes.to_le_bytes());
                }
            }
        }
        out
    }
}

/// Stable framing tag for one registry kind.
const fn kind_tag(kind: DirectiveKind) -> u8 {
    match kind {
        DirectiveKind::RerunIfChanged => 1,
        DirectiveKind::RerunIfEnvChanged => 2,
        DirectiveKind::RustcEnv => 3,
        DirectiveKind::RustcFlags => 4,
        DirectiveKind::RustcLinkLib => 5,
        DirectiveKind::RustcLinkSearch => 6,
        DirectiveKind::RustcCdylibLinkArg => 7,
        DirectiveKind::Warning => 8,
        DirectiveKind::Metadata => 9,
        DirectiveKind::DepInfo => 10,
        DirectiveKind::Unknown => 11,
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_chunker::CanonicalObservation as Obs;

    fn stdout_line(seq: u64, text: &[u8]) -> Obs {
        let mut bytes = text.to_vec();
        bytes.push(b'\n');
        Obs::Line {
            stream: StdStream::Stdout,
            seq,
            bytes,
        }
    }

    fn stderr_line(seq: u64, text: &[u8]) -> Obs {
        let mut bytes = text.to_vec();
        bytes.push(b'\n');
        Obs::Line {
            stream: StdStream::Stderr,
            seq,
            bytes,
        }
    }

    #[test]
    fn n002_directives_parse_in_stdout_order_across_interleaving() {
        // Interleaved writes: stderr chatter BETWEEN directives must not
        // disturb stdout order, and each directive keeps its TRUE shared
        // arrival sequence.
        let transcript = vec![
            stdout_line(1, b"building probe"),
            stderr_line(2, b"warming cache"),
            stdout_line(3, b"cargo:rerun-if-changed=build.rs"),
            stderr_line(4, b"cc some-dependency.c"),
            stdout_line(5, b"cargo:rustc-env=N001_GENERATED=1"),
            stdout_line(6, b"plain stdout tail"),
            stdout_line(7, b"cargo:warning=watch out"),
        ];
        let manifest = extract_directives(&transcript).expect("ordered transcript");
        assert_eq!(manifest.schema_version, DIRECTIVE_MANIFEST_SCHEMA_VERSION);
        let seqs: Vec<u64> = manifest.entries.iter().map(|e| e.seq()).collect();
        assert_eq!(seqs, vec![3, 5, 7], "stdout order, true shared seqs");
        assert!(!manifest.has_unparsed_spills());

        {
            let ManifestEntry::Directive {
                kind,
                key,
                value,
                raw_line,
                ..
            } = &manifest.entries[0]
            else {
                panic!("entry 1 must be a directive");
            };
            assert_eq!(*kind, DirectiveKind::RerunIfChanged);
            assert_eq!(key, b"rerun-if-changed");
            assert_eq!(value.as_deref(), Some(b"build.rs".as_slice()));
            assert_eq!(raw_line, b"cargo:rerun-if-changed=build.rs\n");
        }
        // rustc-env splits on FIRST '=' only; interior '=' stays value.
        {
            let ManifestEntry::Directive { value, .. } = &manifest.entries[1] else {
                panic!("entry 2 must be a directive");
            };
            assert_eq!(value.as_deref(), Some(b"N001_GENERATED=1".as_slice()));
        }
        assert_eq!(
            manifest
                .values_of(DirectiveKind::Warning)
                .collect::<Vec<_>>(),
            vec![b"watch out".as_slice()]
        );
    }

    #[test]
    fn n002_unknown_keys_and_key_only_lines_are_captured_faithfully() {
        let transcript = vec![
            stdout_line(1, b"cargo:rerun-if-changed=src"),
            stdout_line(2, b"cargo:some-future-directive=v1"),
            stdout_line(3, b"cargo:bare-key-no-value"),
            stdout_line(4, b"cargo:METADATA=mixed-case-is-unknown"),
        ];
        let manifest = extract_directives(&transcript).expect("parses");
        assert_eq!(manifest.entries.len(), 4, "every cargo: line is an entry");
        {
            let ManifestEntry::Directive {
                kind,
                key,
                value,
                raw_line,
                ..
            } = &manifest.entries[1]
            else {
                panic!("entry 2 must be a directive");
            };
            assert_eq!(*kind, DirectiveKind::Unknown);
            assert_eq!(key, b"some-future-directive");
            assert_eq!(value.as_deref(), Some(b"v1".as_slice()));
            assert_eq!(raw_line, b"cargo:some-future-directive=v1\n");
        }
        {
            let ManifestEntry::Directive {
                kind, value, key, ..
            } = &manifest.entries[2]
            else {
                panic!("entry 3 must be a directive");
            };
            assert_eq!(*kind, DirectiveKind::Unknown);
            assert_eq!(key, b"bare-key-no-value");
            assert_eq!(*value, None, "key-only directive has no value");
        }
        // Case-sensitivity: cargo matches keys exactly; METADATA is not
        // the metadata directive.
        {
            let ManifestEntry::Directive { kind, .. } = &manifest.entries[3] else {
                panic!("entry 4 must be a directive");
            };
            assert_eq!(*kind, DirectiveKind::Unknown);
        }
        // And the real metadata key classifies correctly.
        let meta =
            extract_directives(&[stdout_line(9, b"cargo:metadata=DEP_X=y")]).expect("parses");
        assert!(matches!(
            meta.entries[0],
            ManifestEntry::Directive {
                kind: DirectiveKind::Metadata,
                ..
            }
        ));
    }

    #[test]
    fn n002_spilled_stdout_lines_are_loud_gaps_not_silence() {
        let transcript = vec![
            stdout_line(1, b"cargo:rerun-if-changed=build.rs"),
            Obs::SpilledLine {
                stream: StdStream::Stdout,
                seq: 2,
                spill_id: 42,
                total_bytes: 9_000_000,
            },
            stdout_line(3, b"cargo:rustc-link-lib=static=probe"),
        ];
        let manifest = extract_directives(&transcript).expect("parses");
        assert!(manifest.has_unparsed_spills(), "gap must be visible");
        assert_eq!(manifest.entries.len(), 3);
        assert!(matches!(
            manifest.entries[1],
            ManifestEntry::UnparsedSpill {
                spill_id: 42,
                total_bytes: 9_000_000,
                ..
            }
        ));
        // Directives around the gap keep their true sequences.
        assert_eq!(manifest.entries[0].seq(), 1);
        assert_eq!(manifest.entries[2].seq(), 3);
        assert_eq!(
            manifest
                .values_of(DirectiveKind::RustcLinkLib)
                .collect::<Vec<_>>(),
            vec![b"static=probe".as_slice()]
        );
    }

    #[test]
    fn n002_crlf_values_and_empty_values_are_byte_exact() {
        let crlf_line = b"cargo:rustc-env=KEY=value\r\n".to_vec();
        let transcript = vec![
            Obs::Line {
                stream: StdStream::Stdout,
                seq: 1,
                bytes: crlf_line.clone(),
            },
            stdout_line(2, b"cargo:rerun-if-changed="),
            Obs::TerminalExit { code: 0 },
        ];
        let manifest = extract_directives(&transcript).expect("parses");
        {
            let ManifestEntry::Directive {
                value, raw_line, ..
            } = &manifest.entries[0]
            else {
                panic!("entry 1 must be a directive");
            };
            assert_eq!(
                value.as_deref(),
                Some(b"KEY=value".as_slice()),
                "\\r stripped once; interior '=' stays in the value"
            );
            assert_eq!(raw_line, &crlf_line, "raw bytes untouched");
        }
        {
            let ManifestEntry::Directive { kind, value, .. } = &manifest.entries[1] else {
                panic!("entry 2 must be a directive");
            };
            assert_eq!(*kind, DirectiveKind::RerunIfChanged);
            assert_eq!(
                value.as_deref(),
                Some(b"".as_slice()),
                "empty value is Some, not None"
            );
        }
        // TerminalExit contributes nothing.
        assert_eq!(manifest.entries.len(), 2);
    }

    #[test]
    fn n002_out_of_order_transcripts_refuse_instead_of_reordering() {
        let transcript = vec![
            stdout_line(5, b"cargo:warning=later"),
            stdout_line(3, b"cargo:warning=earlier"),
        ];
        assert_eq!(
            extract_directives(&transcript),
            Err(ManifestRefusal::ObservationsOutOfOrder)
        );
        // Equal sequences are equally invented-order.
        let dup = vec![stdout_line(4, b"x"), stdout_line(4, b"y")];
        assert_eq!(
            extract_directives(&dup),
            Err(ManifestRefusal::ObservationsOutOfOrder)
        );
        // Stderr sequences participate in the SAME ordering check.
        let mixed = vec![stdout_line(6, b"a"), stderr_line(2, b"b")];
        assert_eq!(
            extract_directives(&mixed),
            Err(ManifestRefusal::ObservationsOutOfOrder)
        );
    }

    #[test]
    fn n002_canonical_bytes_are_deterministic_and_entry_sensitive() {
        let mk = |with_spill: bool| {
            let mut t = vec![stdout_line(1, b"cargo:rerun-if-changed=build.rs")];
            if with_spill {
                t.push(Obs::SpilledLine {
                    stream: StdStream::Stdout,
                    seq: 2,
                    spill_id: 9,
                    total_bytes: 500,
                });
            }
            extract_directives(&t).expect("valid")
        };
        let base = mk(false).canonical_bytes();
        assert_eq!(base, mk(false).canonical_bytes(), "deterministic");
        assert_ne!(
            base,
            mk(true).canonical_bytes(),
            "spill entry changes framing"
        );
        // Value change changes framing.
        let alt = extract_directives(&[stdout_line(1, b"cargo:rerun-if-changed=other.rs")])
            .expect("valid")
            .canonical_bytes();
        assert_ne!(base, alt);
    }
}
