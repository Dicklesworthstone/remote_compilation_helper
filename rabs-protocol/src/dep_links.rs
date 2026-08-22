//! `DEP_<LINKS>_<KEY>` environment reconstruction on replay (bead N004;
//! plan §196 Epic N; consumes [`crate::directive_manifest::DirectiveManifest`]).
//!
//! When a build script's package declares `links`, cargo exports its
//! directives to DEPENDENT build scripts as `DEP_<LINKS>_<KEY>=VALUE`
//! environment variables. A run-cache replay must reproduce those vars
//! EXACTLY — downstream keys and execution depend on them — without
//! re-running anything.
//!
//! THE RULES BELOW ARE MEASURED, NOT REMEMBERED (probes against stable
//! and nightly 2026-08-22 produced identical results; see the tests,
//! which encode the observed table):
//!
//! - NAME: `DEP_` + MANGLE(links) + `_` + MANGLE(directive-key), where
//!   MANGLE uppercases ASCII letters and maps `-` to `_`
//!   (`"Sys-Probe_v1"` → `"SYS_PROBE_V1"`; `"hyphen-key"` →
//!   `"HYPHEN_KEY"`);
//! - VALUE: everything after the FIRST `=` of the original directive
//!   line, byte-exact (`cargo:Mixed==equals==inside` yields value
//!   `=equals==inside`);
//! - FORWARDING SET: only directives cargo does NOT consume itself are
//!   exported — measured: `cargo:metadata=*` forwards; UNKNOWN keys
//!   forward; `rustc-env`, `rerun-if-changed`, `warning`,
//!   `rustc-link-search` do NOT (consumed by cargo). We therefore
//!   forward [`DirectiveKind::Metadata`] and [`DirectiveKind::Unknown`],
//!   and skip every other registered kind;
//! - COLLISIONS: later same-name entries OVERWRITE earlier ones
//!   (last-write-wins, measured with repeated `cargo:metadata=` lines).
//!
//! Honesty valve: an oversized (spilled) stdout line could hide a
//! forwarding directive that capture could not parse. Reconstruction
//! counts those gaps instead of papering over them; callers gate
//! serving on zero gaps (same posture as N014).

use crate::directive_manifest::{DirectiveKind, DirectiveManifest, ManifestEntry};

/// Mangle one name component per the measured rule: ASCII-uppercase,
/// `-` becomes `_`, all other bytes pass through unchanged.
#[must_use]
pub fn mangle_component(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| match b {
            b'a'..=b'z' => b - 32,
            b'-' => b'_',
            _ => b,
        })
        .collect()
}

/// The full `DEP_<LINKS>_<KEY>` variable name for one directive.
#[must_use]
pub fn dep_env_name(links: &[u8], key: &[u8]) -> Vec<u8> {
    let mut name = b"DEP_".to_vec();
    name.extend_from_slice(&mangle_component(links));
    name.push(b'_');
    name.extend_from_slice(&mangle_component(key));
    name
}

/// Whether cargo forwards this directive kind to dependents. MEASURED:
/// metadata and unknown keys forward; everything else is consumed by
/// cargo before dependents ever see it.
#[must_use]
pub const fn is_forwarded(kind: DirectiveKind) -> bool {
    matches!(kind, DirectiveKind::Metadata | DirectiveKind::Unknown)
}

/// The reconstructed `DEP_*` environment for dependent build scripts,
/// plus the honesty counters a serving decision needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DepEnvReconstruction {
    /// Final variables in FIRST-APPEARANCE order (collisions resolved
    /// last-write-wins, matching cargo's observed overwrite behavior).
    pub vars: Vec<(Vec<u8>, Vec<u8>)>,
    /// Spilled stdout lines that could not be parsed: each may hide a
    /// forwarding directive. Serving must refuse while this is nonzero.
    pub unparsed_spill_count: usize,
}

impl DepEnvReconstruction {
    /// Whether the reconstruction is complete enough to serve from
    /// (no hidden-line gaps).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.unparsed_spill_count == 0
    }
}

/// Reconstruct the `DEP_*` environment a dependent build script would
/// observe, given the provider package's `links` value and the captured
/// directive manifest.
///
/// Deterministic: same manifest + links ⇒ same vars, always.
#[must_use]
pub fn reconstruct_dep_env(links: &[u8], manifest: &DirectiveManifest) -> DepEnvReconstruction {
    // Insertion order preserved; last-write-wins by replacement.
    let mut vars: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut spill_count = 0usize;

    for entry in &manifest.entries {
        match entry {
            ManifestEntry::Directive {
                kind, key, value, ..
            } => {
                if !is_forwarded(*kind) {
                    continue;
                }
                let name = dep_env_name(links, key);
                let val = value.clone().unwrap_or_default();
                if let Some(slot) = vars.iter_mut().find(|(n, _)| *n == name) {
                    slot.1 = val;
                } else {
                    vars.push((name, val));
                }
            }
            ManifestEntry::UnparsedSpill { .. } => {
                spill_count += 1;
            }
        }
    }

    DepEnvReconstruction {
        vars,
        unparsed_spill_count: spill_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directive_manifest::extract_directives;
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

    /// MEASURED on stable + nightly (probe round 2): distinct keys,
    /// case/hyphen mangling, interior-'=' values.
    #[test]
    fn n004_mangling_matches_measured_cargo_behavior() {
        let manifest = manifest_of(&[
            b"cargo:PlainKey=plain-value",
            b"cargo:lower_case=lw",
            b"cargo:Mixed==equals==inside",
            b"cargo:hyphen-key=hv",
        ]);
        let rec = reconstruct_dep_env(b"Sys-Probe_v1", &manifest);
        assert!(rec.is_complete());
        let expected: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                b"DEP_SYS_PROBE_V1_PLAINKEY".to_vec(),
                b"plain-value".to_vec(),
            ),
            (b"DEP_SYS_PROBE_V1_LOWER_CASE".to_vec(), b"lw".to_vec()),
            (
                b"DEP_SYS_PROBE_V1_MIXED".to_vec(),
                b"=equals==inside".to_vec(),
            ),
            (b"DEP_SYS_PROBE_V1_HYPHEN_KEY".to_vec(), b"hv".to_vec()),
        ];
        assert_eq!(rec.vars, expected, "must equal the observed env table");
    }

    /// MEASURED (probe round 3): cargo-consumed kinds never reach
    /// dependents; custom keys and metadata do.
    #[test]
    fn n004_consumed_kinds_are_excluded_metadata_and_unknown_forward() {
        let manifest = manifest_of(&[
            b"cargo:rustc-env=RUSTC_ENV_VAR=rv",
            b"cargo:rerun-if-changed=build.rs",
            b"cargo:warning=a-warning",
            b"cargo:rustc-link-search=native=/tmp",
            b"cargo:custom_key=cv",
            b"cargo:metadata=DEP_X=y",
        ]);
        let rec = reconstruct_dep_env(b"probe", &manifest);
        let names: Vec<Vec<u8>> = rec.vars.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(
            names,
            vec![
                b"DEP_PROBE_CUSTOM_KEY".to_vec(),
                b"DEP_PROBE_METADATA".to_vec(),
            ],
            "exactly the forwarded set, first-appearance order"
        );
        assert_eq!(rec.vars[0].1, b"cv".to_vec());
        assert_eq!(rec.vars[1].1, b"DEP_X=y".to_vec());
    }

    /// MEASURED (probe round 1): repeated var name overwrites — only the
    /// last value survives.
    #[test]
    fn n004_collisions_resolve_last_write_wins() {
        let manifest = manifest_of(&[
            b"cargo:metadata=first",
            b"cargo:metadata=second",
            b"cargo:metadata=hyphen-key=hv",
        ]);
        let rec = reconstruct_dep_env(b"Sys-Probe_v1", &manifest);
        assert_eq!(
            rec.vars,
            vec![(
                b"DEP_SYS_PROBE_V1_METADATA".to_vec(),
                b"hyphen-key=hv".to_vec(),
            )],
            "single var, final value"
        );
    }

    #[test]
    fn n004_spill_gaps_are_counted_and_block_completeness() {
        let mut obs = vec![stdout_line(1, b"cargo:metadata=known")];
        obs.push(Obs::SpilledLine {
            stream: StdStream::Stdout,
            seq: 2,
            spill_id: 7,
            total_bytes: 123,
        });
        let manifest = extract_directives(&obs).expect("valid");
        let rec = reconstruct_dep_env(b"probe", &manifest);
        assert_eq!(rec.unparsed_spill_count, 1);
        assert!(!rec.is_complete(), "hidden line must block serving");
        // The known var still reconstructs; completeness is the gate.
        assert_eq!(rec.vars.len(), 1);
    }

    #[test]
    fn n004_mangle_is_ascii_scoped_and_byte_transparent() {
        assert_eq!(mangle_component(b"Sys-Probe_v1"), b"SYS_PROBE_V1");
        assert_eq!(mangle_component(b"hyphen-key"), b"HYPHEN_KEY");
        // Non-ASCII passes through untouched (cargo would reject such a
        // links value upstream anyway; reconstruction mirrors, never
        // invents).
        assert_eq!(mangle_component(b"a\xffz"), b"A\xffZ");
    }
}
