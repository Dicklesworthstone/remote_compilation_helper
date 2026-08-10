//! Layer 0 configuration pack (bead B014; milestone M-1 core).
//!
//! Before RABS proper, the cheapest wins are configuration: better
//! profiles, faster linkers, a stable command palette. This module is
//! the VERSIONED pack — every knob independently toggleable, every
//! capability DETECTED from evidence rather than assumed, and the
//! whole pack rendered deterministically so two machines with the
//! same evidence emit byte-identical config:
//!
//! - **Capability detection is exact.** `-Zthreads` turns on only
//!   when the rustc version string proves a supported nightly —
//!   never an unconditional unstable flag; a stable or unknown
//!   toolchain yields a typed "not supported" with the evidence
//!   echoed. Linker selection reuses the F-series
//!   [`crate::linker_profiles::detect_family`] preference order
//!   (Wild > lld > system) over REAL `--version` output.
//! - **Every knob carries its lane and its kill condition.** The
//!   B014 KILL rule (any knob that regresses representative p95,
//!   output equivalence, debugger behavior, or compatibility leaves
//!   the defaults) is IN the knob metadata: a knob renders into
//!   config only while `enabled`, and flipping one off never touches
//!   the others.
//! - **The agent command palette is part of the pack** because a
//!   stable palette (fixed check profile, fixed nextest invocation,
//!   fixed feature/target/lint spelling, explicit doctest policy)
//!   directly reduces future action-key fragmentation.
//! - **Benchmark gating is a deployment precondition, not a claim.**
//!   This module produces the pack and its knob inventory; the
//!   representative-p95 verdicts come from B008 reports on real
//!   hardware, and [`Knob::benchmark_verdict`] starts `Ungated` —
//!   a pack consumer can require `Kept` verdicts before enabling
//!   anything beyond the safe core.

use crate::linker_profiles::{LinkerFamily, detect_family};

/// Pack schema version (bump on any semantic change to a knob).
pub const LAYER0_PACK_VERSION: u32 = 1;

/// The benchmark verdict a knob carries (B014's KILL rule made data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkVerdict {
    /// No representative benchmark has judged this knob yet: consumers
    /// wanting the KILL discipline treat it as not-yet-enableable.
    Ungated,
    /// Benchmarked and kept (no p95/equivalence/debugger/compat
    /// regression in the intended lane).
    Kept,
    /// Benchmarked and KILLED: the knob regressed; defaults stay.
    Killed {
        /// Which axis regressed.
        regressed: &'static str,
    },
}

/// One independently toggleable knob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knob {
    /// Stable knob id.
    pub id: &'static str,
    /// Whether the knob is on.
    pub enabled: bool,
    /// The benchmark verdict.
    pub benchmark_verdict: BenchmarkVerdict,
    /// The `.cargo/config.toml` / `Cargo.toml` fragment this knob
    /// contributes when enabled (deterministic text).
    pub fragment: String,
}

/// Evidence for `-Zthreads` support: the rustc version line.
/// Supported = a nightly at or past 1.98 (parallel frontend soak
/// window per the plan); anything else — stable, beta, older nightly,
/// unparseable — is typed unsupported with the line echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZThreadsSupport {
    /// Proven supported by the version evidence.
    Supported {
        /// The nightly version that proved it.
        version: String,
    },
    /// Not supported (or not proven); the evidence is echoed.
    Unsupported {
        /// The version line examined.
        evidence: String,
    },
}

/// Detect `-Zthreads` support from `rustc --version` output.
#[must_use]
pub fn detect_zthreads(rustc_version_line: &str) -> ZThreadsSupport {
    let line = rustc_version_line.trim();
    // Shape: "rustc 1.99.0-nightly (abcdef 2026-07-01)".
    let unsupported = || ZThreadsSupport::Unsupported {
        evidence: line.to_owned(),
    };
    let Some(rest) = line.strip_prefix("rustc ") else {
        return unsupported();
    };
    let Some((semver, _)) = rest.split_once(' ') else {
        return unsupported();
    };
    if !semver.ends_with("-nightly") {
        return unsupported();
    }
    let core = semver.trim_end_matches("-nightly");
    let mut parts = core.split('.');
    let (Some(major), Some(minor)) = (
        parts.next().and_then(|p| p.parse::<u32>().ok()),
        parts.next().and_then(|p| p.parse::<u32>().ok()),
    ) else {
        return unsupported();
    };
    if major > 1 || (major == 1 && minor >= 98) {
        ZThreadsSupport::Supported {
            version: semver.to_owned(),
        }
    } else {
        unsupported()
    }
}

/// The canonical agent command palette: ONE spelling per operation, so
/// agent-issued commands stop fragmenting future action keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPalette {
    /// The standard check invocation.
    pub check: &'static str,
    /// The standard test invocation (nextest).
    pub test: &'static str,
    /// The standard lint invocation.
    pub lint: &'static str,
    /// Doctest policy: explicit, not ambient.
    pub doctests: &'static str,
}

/// The v1 palette. Fixed spellings — flags in one canonical order,
/// workspace-wide scope, locked toolchain-agnostic wording.
pub const PALETTE_V1: CommandPalette = CommandPalette {
    check: "cargo check --workspace --all-targets",
    test: "cargo nextest run --workspace",
    lint: "cargo clippy --workspace --all-targets -- -D warnings",
    doctests: "cargo test --workspace --doc",
};

/// Inputs to pack assembly: detection evidence, all caller-supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackEvidence {
    /// `rustc --version` line.
    pub rustc_version_line: String,
    /// Linker `--version` first lines, in discovery order.
    pub linker_version_lines: Vec<String>,
    /// Whether `sccache` is on PATH (the caller probed).
    pub sccache_available: bool,
    /// Whether `cargo hakari` is installed (the caller probed).
    pub hakari_available: bool,
}

/// The assembled pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer0Pack {
    /// Pack version.
    pub version: u32,
    /// Every knob, enabled or not — the inventory is always complete.
    pub knobs: Vec<Knob>,
    /// The palette (always present; it is spelling, not a knob).
    pub palette: CommandPalette,
}

/// Assemble the pack from evidence. Deterministic: same evidence,
/// same pack, byte-identical fragments.
#[must_use]
pub fn assemble(evidence: &PackEvidence) -> Layer0Pack {
    let mut knobs = Vec::new();

    // Debuginfo reduction: safe-core default-on (line-tables-only for
    // dev; full debuginfo stays available via the debug profile lane).
    knobs.push(Knob {
        id: "debuginfo-line-tables-only",
        enabled: true,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: "[profile.dev]\ndebug = \"line-tables-only\"\n".to_owned(),
    });
    // Unpacked split debuginfo (macOS/Linux dev-lane).
    knobs.push(Knob {
        id: "split-debuginfo-unpacked",
        enabled: true,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: "[profile.dev]\nsplit-debuginfo = \"unpacked\"\n".to_owned(),
    });

    // -Zthreads: exact capability detection, never unconditional.
    match detect_zthreads(&evidence.rustc_version_line) {
        ZThreadsSupport::Supported { version } => knobs.push(Knob {
            id: "zthreads-parallel-frontend",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# proven by {version}\n[build]\nrustflags = [\"-Zthreads=8\"]\n"),
        }),
        ZThreadsSupport::Unsupported { evidence } => knobs.push(Knob {
            id: "zthreads-parallel-frontend",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# disabled: not proven by \"{evidence}\"\n"),
        }),
    }

    // Linker: the F-series preference order over real version output.
    let best = evidence
        .linker_version_lines
        .iter()
        .map(|line| (detect_family(line), line))
        .min_by_key(|(family, _)| {
            LinkerFamily::PREFERENCE
                .iter()
                .position(|p| p == family)
                .unwrap_or(usize::MAX)
        });
    match best {
        Some((LinkerFamily::Wild, line)) => knobs.push(Knob {
            id: "linker-wild",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# detected: {line}\n[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=--ld-path=wild\"]\n"
            ),
        }),
        Some((LinkerFamily::Lld, line)) => knobs.push(Knob {
            id: "linker-lld",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# detected: {line}\n[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=-fuse-ld=lld\"]\n"
            ),
        }),
        _ => knobs.push(Knob {
            id: "linker-system",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# no faster linker detected; system default stays\n".to_owned(),
        }),
    }

    // cargo-hakari workspace-hack: only when the tool is present.
    knobs.push(Knob {
        id: "hakari-workspace-hack",
        enabled: evidence.hakari_available,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: if evidence.hakari_available {
            "# run: cargo hakari init workspace-hack && cargo hakari generate\n".to_owned()
        } else {
            "# disabled: cargo-hakari not installed\n".to_owned()
        },
    });

    // sccache baseline: only when present.
    knobs.push(Knob {
        id: "sccache-baseline",
        enabled: evidence.sccache_available,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: if evidence.sccache_available {
            "[build]\nrustc-wrapper = \"sccache\"\n".to_owned()
        } else {
            "# disabled: sccache not on PATH\n".to_owned()
        },
    });

    Layer0Pack {
        version: LAYER0_PACK_VERSION,
        knobs,
        palette: PALETTE_V1,
    }
}

impl Layer0Pack {
    /// Render the enabled knobs' fragments under a versioned header,
    /// MERGED BY SECTION: fragments naming the same `[table]` fold into
    /// one table body (TOML rejects duplicate table headers — found
    /// live when B015 fed the rendered config to `cargo --config`).
    /// Section first-appearance order and in-section knob order both
    /// follow inventory order. Disabled knobs contribute NOTHING (their
    /// reasons live in the inventory, not the output).
    #[must_use]
    pub fn render_config(&self) -> String {
        let mut section_order: Vec<String> = Vec::new();
        let mut sections: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for knob in self.knobs.iter().filter(|k| k.enabled) {
            let mut current = String::new(); // "" = preamble (comments)
            for line in knob.fragment.lines() {
                if line.starts_with('[') {
                    current = line.to_string();
                    if !sections.contains_key(&current) {
                        section_order.push(current.clone());
                        sections.insert(current.clone(), String::new());
                    }
                    let body = sections.get_mut(&current).expect("just inserted");
                    body.push_str(&format!("# knob: {}\n", knob.id));
                } else {
                    let body = sections.entry(current.clone()).or_insert_with(|| {
                        section_order.push(current.clone());
                        String::new()
                    });
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
        let mut out = format!("# rabs layer0 pack v{}\n", self.version);
        for section in &section_order {
            out.push('\n');
            if !section.is_empty() {
                out.push_str(section);
                out.push('\n');
            }
            out.push_str(&sections[section]);
        }
        out
    }

    /// Disable one knob by id (the independent-toggle guarantee).
    /// Unknown ids are reported, not ignored.
    ///
    /// # Errors
    /// The unknown id.
    pub fn disable(&mut self, id: &str) -> Result<(), String> {
        match self.knobs.iter_mut().find(|k| k.id == id) {
            Some(knob) => {
                knob.enabled = false;
                Ok(())
            }
            None => Err(id.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_config_has_no_duplicate_table_headers() {
        // TOML rejects duplicate [table] headers; multiple knobs share
        // [profile.dev], so render must merge (found live in B015 when
        // cargo --config refused the rendered pack).
        let pack = assemble(&evidence("release: 1.99.0-nightly", &["LLD 18.0"]));
        let rendered = pack.render_config();
        let mut seen = std::collections::BTreeSet::new();
        for line in rendered.lines() {
            if line.starts_with('[') {
                assert!(
                    seen.insert(line.to_string()),
                    "duplicate table header {line} in:\n{rendered}"
                );
            }
        }
        assert!(rendered.contains("[profile.dev]"));
    }

    fn evidence(rustc: &str, linkers: &[&str]) -> PackEvidence {
        PackEvidence {
            rustc_version_line: rustc.to_owned(),
            linker_version_lines: linkers.iter().map(|s| (*s).to_owned()).collect(),
            sccache_available: true,
            hakari_available: false,
        }
    }

    #[test]
    fn b014_zthreads_is_exact_capability_detection_never_unconditional() {
        // Supported nightly: on.
        assert!(matches!(
            detect_zthreads("rustc 1.99.0-nightly (abc 2026-07-01)"),
            ZThreadsSupport::Supported { .. }
        ));
        // Stable, beta, old nightly, garbage: all typed-unsupported
        // with the evidence echoed.
        for line in [
            "rustc 1.99.0 (abc 2026-07-01)",
            "rustc 1.99.0-beta.2 (abc 2026-07-01)",
            "rustc 1.97.0-nightly (abc 2026-05-01)",
            "not rustc at all",
            "",
        ] {
            let ZThreadsSupport::Unsupported { evidence } = detect_zthreads(line) else {
                panic!("{line:?} must not enable an unstable flag");
            };
            assert_eq!(evidence, line.trim());
        }
        // And the knob follows: stable evidence → knob disabled, no
        // -Zthreads anywhere in the rendered config.
        let pack = assemble(&evidence("rustc 1.99.0 (abc 2026-07-01)", &[]));
        assert!(!pack.render_config().contains("-Zthreads"));
        let pack = assemble(&evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]));
        assert!(pack.render_config().contains("-Zthreads=8"));
    }

    #[test]
    fn b014_linker_selection_follows_the_preference_order() {
        // Wild beats lld when both are present.
        let pack = assemble(&evidence(
            "rustc 1.99.0-nightly (abc 2026-07-01)",
            &["LLD 18.1.0 (compatible with GNU linkers)", "wild 0.4.0"],
        ));
        assert!(
            pack.knobs
                .iter()
                .any(|k| k.id == "linker-wild" && k.enabled)
        );
        assert!(pack.render_config().contains("--ld-path=wild"));
        // lld alone selects lld.
        let pack = assemble(&evidence(
            "rustc 1.99.0-nightly (abc 2026-07-01)",
            &["LLD 18.1.0 (compatible with GNU linkers)"],
        ));
        assert!(pack.knobs.iter().any(|k| k.id == "linker-lld" && k.enabled));
        // Nothing detected: the system knob exists DISABLED (inventory
        // complete, config untouched).
        let pack = assemble(&evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]));
        let system = pack.knobs.iter().find(|k| k.id == "linker-system").unwrap();
        assert!(!system.enabled);
        assert!(!pack.render_config().contains("linker ="));
    }

    #[test]
    fn b014_knobs_toggle_independently_and_render_deterministically() {
        let e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &["wild 0.4.0"]);
        let mut pack = assemble(&e);
        // Deterministic: same evidence → byte-identical render.
        assert_eq!(pack.render_config(), assemble(&e).render_config());
        // Disabling ONE knob removes exactly its fragment.
        let before = pack.render_config();
        pack.disable("sccache-baseline").unwrap();
        let after = pack.render_config();
        assert!(before.contains("rustc-wrapper = \"sccache\""));
        assert!(!after.contains("rustc-wrapper"));
        assert!(after.contains("-Zthreads=8"), "other knobs untouched");
        assert!(after.contains("--ld-path=wild"), "other knobs untouched");
        // Unknown ids are reported, not ignored.
        assert_eq!(pack.disable("no-such-knob"), Err("no-such-knob".to_owned()));
        // Tool-gated knobs: hakari absent → disabled with reason in
        // the inventory, nothing in the config.
        assert!(
            pack.knobs
                .iter()
                .any(|k| k.id == "hakari-workspace-hack" && !k.enabled)
        );
        assert!(!after.contains("hakari"));
    }

    #[test]
    fn b014_palette_is_fixed_spelling_and_verdicts_start_ungated() {
        let pack = assemble(&evidence("rustc 1.99.0 (abc)", &[]));
        // ONE spelling per operation (key-fragmentation reduction).
        assert_eq!(pack.palette.check, "cargo check --workspace --all-targets");
        assert_eq!(pack.palette.test, "cargo nextest run --workspace");
        assert_eq!(
            pack.palette.lint,
            "cargo clippy --workspace --all-targets -- -D warnings"
        );
        assert_eq!(pack.palette.doctests, "cargo test --workspace --doc");
        // The KILL discipline is data: every knob ships Ungated — the
        // representative-p95 verdict comes from B008 runs on real
        // hardware, never from this module's assembly.
        assert!(
            pack.knobs
                .iter()
                .all(|k| k.benchmark_verdict == BenchmarkVerdict::Ungated)
        );
    }
}
