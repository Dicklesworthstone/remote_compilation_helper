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
//!   when an explicitly requested nightly reports the actual option —
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
use std::num::NonZeroU32;

/// Pack schema version (bump on any semantic change to a knob).
pub const LAYER0_PACK_VERSION: u32 = 4;

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

/// Evidence for `-Zthreads` support: a nightly version line AND successful
/// `rustc -Z help` output from the same compiler. A version alone cannot prove
/// that a custom compiler contains an unstable option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZThreadsSupport {
    /// Nightly identity and successful option evidence agree.
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

/// The nightly semver a `rustc --version` line PROVES, if it proves one.
/// Shape: `rustc 1.99.0-nightly (abcdef 2026-07-01)`. Stable, beta, a
/// doubled `-nightly` suffix, a non-numeric component or a fourth
/// component all prove nothing — every unstable surface in this pack
/// keys off this one check, so it stays strict and shared rather than
/// re-spelled per knob.
fn nightly_semver(version_line: &str) -> Option<&str> {
    let rest = version_line.trim().strip_prefix("rustc ")?;
    let (semver, _) = rest.split_once(' ')?;
    let core = semver.strip_suffix("-nightly")?;
    let mut parts = core.split('.');
    let numeric = [parts.next(), parts.next(), parts.next()].iter().all(|p| {
        p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            && p.is_some_and(|p| p.parse::<u32>().is_ok())
    });
    (numeric && parts.next().is_none()).then_some(semver)
}

/// Detect support from the same compiler's version and successful `-Z help`.
/// `None` means the option probe failed or was not performed. Stable and beta
/// remain unsupported even when a caller uses `RUSTC_BOOTSTRAP`.
#[must_use]
pub fn detect_zthreads(rustc_version_line: &str, z_help: Option<&str>) -> ZThreadsSupport {
    let line = rustc_version_line.trim();
    // Shape: "rustc 1.99.0-nightly (abcdef 2026-07-01)".
    let unsupported = || ZThreadsSupport::Unsupported {
        evidence: line.to_owned(),
    };
    let Some(semver) = nightly_semver(line) else {
        return unsupported();
    };
    let has_threads = z_help.is_some_and(|help| {
        help.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some("-Z") && fields.next() == Some("threads=val")
        })
    });
    if has_threads {
        ZThreadsSupport::Supported {
            version: semver.to_owned(),
        }
    } else {
        unsupported()
    }
}

/// Evidence for the Cranelift codegen backend (L0-e). Cranelift ships only
/// as a nightly component, and a nightly that does not carry the backend
/// library cannot load it — so support needs BOTH the nightly identity and
/// the library that nightly would open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CraneliftSupport {
    /// Nightly identity and a present backend library agree.
    Supported {
        /// The nightly version that proved it.
        version: String,
        /// The backend library the caller found.
        backend: String,
    },
    /// Not supported (or not proven); the evidence is echoed.
    Unsupported {
        /// What was examined.
        evidence: String,
    },
}

/// Detect the Cranelift backend from the compiler's version line and the
/// backend library path the caller probed (`None` = not found / not probed).
/// A stable or beta toolchain is never Cranelift-capable here even when the
/// caller hands over a library path, because `codegen-backend` is unstable.
#[must_use]
pub fn detect_cranelift(
    rustc_version_line: &str,
    backend_library: Option<&str>,
) -> CraneliftSupport {
    let line = rustc_version_line.trim();
    let unsupported = |detail: &str| CraneliftSupport::Unsupported {
        evidence: if detail.is_empty() {
            line.to_owned()
        } else {
            format!("{line} ({detail})")
        },
    };
    let Some(semver) = nightly_semver(line) else {
        return unsupported("");
    };
    match backend_library.map(str::trim).filter(|p| !p.is_empty()) {
        Some(backend) => CraneliftSupport::Supported {
            version: semver.to_owned(),
            backend: backend.to_owned(),
        },
        None => unsupported("no codegen-backends library found"),
    }
}

/// The `-C target-cpu` decision (L0-g).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetCpuDecision {
    /// An explicit, portable baseline to pin.
    Pinned(String),
    /// A machine-relative spelling was requested and REFUSED.
    RefusedNonPortable {
        /// What the caller asked for.
        requested: String,
    },
    /// Nothing requested: the ambient target-cpu stays.
    Unset,
}

/// Resolve a requested target-cpu baseline.
///
/// `native` (and `apple-latest`) resolve to a DIFFERENT cpu on every machine
/// that reads them, which is precisely the action-key fragmentation this pack
/// exists to remove: two workers would compile the same source under two
/// different `-C target-cpu` values while reporting the same config. They are
/// refused with the request echoed rather than silently pinned.
#[must_use]
pub fn resolve_target_cpu(requested: Option<&str>) -> TargetCpuDecision {
    match requested.map(str::trim).filter(|v| !v.is_empty()) {
        None => TargetCpuDecision::Unset,
        Some(value)
            if value.eq_ignore_ascii_case("native")
                || value.eq_ignore_ascii_case("apple-latest") =>
        {
            TargetCpuDecision::RefusedNonPortable {
                requested: value.to_owned(),
            }
        }
        Some(value) => TargetCpuDecision::Pinned(value.to_owned()),
    }
}

/// An Apple SDK baseline: the version that identifies it and the root that
/// pins it (L0-g). Both travel together — a version without a root cannot be
/// pinned, and a root without a version cannot be compared across machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleSdkBaseline {
    /// `xcrun --show-sdk-version` output.
    pub version: String,
    /// `xcrun --show-sdk-path` output.
    pub path: String,
}

/// Why the pack left the system linker in place (L0-c). Every rejection
/// names the evidence, because "no faster linker" and "a faster linker we
/// must not use here" are different operational facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkerRejection {
    /// No `wild`/`lld` version line was collected.
    NotDetected,
    /// A faster linker answered, but the driver that carries the flag is absent.
    DriverMissing {
        /// The version line that would have been selected.
        candidate: String,
    },
    /// The host is not a target whose flag spelling this pack knows.
    UnsupportedHost {
        /// The triple that was rejected.
        triple: String,
    },
}

impl LinkerRejection {
    /// The operator-facing reason, rendered into the knob inventory.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::NotDetected => "no faster linker detected; system default stays".to_owned(),
            Self::DriverMissing { candidate } => format!(
                "detected `{candidate}` but the clang driver that carries the flag is absent; system default stays"
            ),
            Self::UnsupportedHost { triple } => format!(
                "host {triple} has no linker flag spelling in this pack; system default stays"
            ),
        }
    }
}

/// The exact, ordered `cargo-hakari` sequence this pack prescribes (L0-f).
///
/// Feature unification drifts silently: a workspace-hack crate that is stale
/// in one lane rebuilds dependencies that another lane already had warm. The
/// value of a FIXED sequence is that the last entry is a CI gate — `verify`
/// fails when the generated crate no longer matches the workspace, so drift
/// is caught by the pipeline rather than by a slow build nobody attributes.
pub const HAKARI_PLAN: [&str; 4] = [
    "cargo hakari init workspace-hack",
    "cargo hakari generate",
    "cargo hakari manage-deps",
    "cargo hakari verify",
];

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
    /// Successful `-Z help` stdout from that same compiler; failed probes are None.
    pub rustc_z_help: Option<String>,
    /// Explicit operator opt-in. None leaves the unstable flag absent.
    pub zthreads: Option<NonZeroU32>,
    /// Explicit opt-in to source lines without variable/type debug information.
    pub line_tables_only: bool,
    /// Explicit opt-in to separate debug files, which must accompany the binary.
    pub split_debuginfo_unpacked: bool,
    /// Linker `--version` first lines, in discovery order.
    pub linker_version_lines: Vec<String>,
    /// The host triple the same compiler reports (`rustc -vV` `host:` line).
    /// Every `[target.*]` section this pack renders is keyed on it; a section
    /// written for another triple is silently inert, which would turn an
    /// "enabled" linker knob into a lie.
    pub host_target_triple: String,
    /// Whether the `clang` driver that carries `--ld-path`/`-fuse-ld` is
    /// present (the caller probed). Naming a linker the host cannot invoke
    /// breaks every build the rendered config touches.
    pub linker_driver_available: bool,
    /// The Cranelift backend library the caller found in the compiler's
    /// `codegen-backends` directory, when it is installed.
    pub cranelift_backend_library: Option<String>,
    /// Explicit opt-in to the Cranelift dev backend. None leaves codegen alone.
    pub cranelift_dev_backend: bool,
    /// Explicit `-C target-cpu` baseline; machine-relative spellings refused.
    pub target_cpu_baseline: Option<String>,
    /// Explicit Apple deployment target (e.g. `13.0`) for Apple hosts.
    pub apple_deployment_target: Option<String>,
    /// The Apple SDK baseline for Apple hosts.
    pub apple_sdk: Option<AppleSdkBaseline>,
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

    // Debugging tradeoffs require explicit opt-in. An unconfigured pack leaves
    // Cargo's debug profile and target-specific split defaults untouched.
    knobs.push(Knob {
        id: "debuginfo-line-tables-only",
        enabled: evidence.line_tables_only,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: "[profile.dev]\ndebug = \"line-tables-only\"\n".to_owned(),
    });
    // Retain the separate files when debugging an unpacked artifact.
    knobs.push(Knob {
        id: "split-debuginfo-unpacked",
        enabled: evidence.split_debuginfo_unpacked,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: "[profile.dev]\nsplit-debuginfo = \"unpacked\"\n".to_owned(),
    });

    // -Zthreads: exact capability detection, never unconditional.
    match (
        evidence.zthreads,
        detect_zthreads(
            &evidence.rustc_version_line,
            evidence.rustc_z_help.as_deref(),
        ),
    ) {
        (Some(threads), ZThreadsSupport::Supported { version }) => knobs.push(Knob {
            id: "zthreads-parallel-frontend",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# option reported by {version}\n[build]\nrustflags = [\"-Zthreads={threads}\"]\n"
            ),
        }),
        _ => knobs.push(Knob {
            id: "zthreads-parallel-frontend",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# disabled: explicit opt-in and compiler capability required\n".to_owned(),
        }),
    }

    // Cranelift dev backend: unstable, so the same exact-detection rule as
    // -Zthreads applies. Build scripts and proc macros are pinned BACK to
    // LLVM: they run during the build (a slower proc macro costs more than
    // the backend saves) and they are the code most likely to use features
    // Cranelift does not implement.
    match (
        evidence.cranelift_dev_backend,
        detect_cranelift(
            &evidence.rustc_version_line,
            evidence.cranelift_backend_library.as_deref(),
        ),
    ) {
        (true, CraneliftSupport::Supported { version, backend }) => knobs.push(Knob {
            id: "codegen-backend-cranelift",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# backend loaded by {version}: {backend}\n[unstable]\ncodegen-backend = true\n[profile.dev]\ncodegen-backend = \"cranelift\"\n[profile.dev.build-override]\ncodegen-backend = \"llvm\"\n"
            ),
        }),
        _ => knobs.push(Knob {
            id: "codegen-backend-cranelift",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# disabled: explicit opt-in and an installed nightly backend required\n"
                .to_owned(),
        }),
    }

    // Linker: the F-series preference order over real version output, gated
    // on the host actually being able to USE the selection. A `[target.<t>]`
    // section for the wrong triple is inert, and `linker = "clang"` without
    // clang breaks every build — both would render an "enabled" knob that
    // does nothing or does harm.
    let elf_host = evidence.host_target_triple.contains("-linux-");
    let candidate = evidence
        .linker_version_lines
        .iter()
        .map(|line| (detect_family(line), line))
        .filter(|(family, _)| matches!(family, LinkerFamily::Wild | LinkerFamily::Lld))
        .min_by_key(|(family, _)| {
            LinkerFamily::PREFERENCE
                .iter()
                .position(|p| p == family)
                .unwrap_or(usize::MAX)
        });
    let selected = match candidate {
        None => Err(LinkerRejection::NotDetected),
        Some(_) if !elf_host => Err(LinkerRejection::UnsupportedHost {
            triple: evidence.host_target_triple.clone(),
        }),
        Some((_, line)) if !evidence.linker_driver_available => {
            Err(LinkerRejection::DriverMissing {
                candidate: line.clone(),
            })
        }
        Some((family, line)) => Ok((family, line)),
    };
    let triple = &evidence.host_target_triple;
    match &selected {
        Ok((LinkerFamily::Wild, line)) => knobs.push(Knob {
            id: "linker-wild",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# detected: {line}\n[target.{triple}]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=--ld-path=wild\"]\n"
            ),
        }),
        Ok((LinkerFamily::Lld, line)) => knobs.push(Knob {
            id: "linker-lld",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# detected: {line}\n[target.{triple}]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=-fuse-ld=lld\"]\n"
            ),
        }),
        Ok((LinkerFamily::System, _)) => knobs.push(Knob {
            id: "linker-system",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# {}\n", LinkerRejection::NotDetected.explain()),
        }),
        Err(rejection) => knobs.push(Knob {
            id: "linker-system",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# {}\n", rejection.explain()),
        }),
    }

    // target-cpu: explicit and portable, or nothing. Pinning the baseline is
    // what stops two workers from compiling the same source under two
    // different implied cpus while reporting the same pack.
    match resolve_target_cpu(evidence.target_cpu_baseline.as_deref()) {
        TargetCpuDecision::Pinned(cpu) => knobs.push(Knob {
            id: "target-cpu-baseline",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("[target.{triple}]\nrustflags = [\"-C\", \"target-cpu={cpu}\"]\n"),
        }),
        TargetCpuDecision::RefusedNonPortable { requested } => knobs.push(Knob {
            id: "target-cpu-baseline",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# refused: target-cpu={requested} resolves per-machine; pin an explicit baseline\n"
            ),
        }),
        TargetCpuDecision::Unset => knobs.push(Knob {
            id: "target-cpu-baseline",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# disabled: no explicit baseline requested; ambient target-cpu stays\n"
                .to_owned(),
        }),
    }

    // Apple baselines. The deployment target and the SDK are the two inputs
    // that drift between machines without anyone changing a config file, so
    // they are pinned as data on Apple hosts and inert everywhere else.
    let apple_host = triple.contains("-apple-");
    let deployment_var = if triple.contains("-apple-ios") {
        "IPHONEOS_DEPLOYMENT_TARGET"
    } else {
        "MACOSX_DEPLOYMENT_TARGET"
    };
    match (apple_host, evidence.apple_deployment_target.as_deref()) {
        (true, Some(version)) if !version.trim().is_empty() => knobs.push(Knob {
            id: "apple-deployment-target",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("[env]\n{deployment_var} = \"{}\"\n", version.trim()),
        }),
        (true, _) => knobs.push(Knob {
            id: "apple-deployment-target",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# disabled: Apple host with no explicit deployment target requested\n"
                .to_owned(),
        }),
        (false, _) => knobs.push(Knob {
            id: "apple-deployment-target",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# disabled: {triple} is not an Apple host\n"),
        }),
    }
    match (apple_host, evidence.apple_sdk.as_ref()) {
        (true, Some(sdk)) if !sdk.path.trim().is_empty() => knobs.push(Knob {
            id: "apple-sdk-baseline",
            enabled: true,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!(
                "# sdk baseline: {}\n[env]\nSDKROOT = \"{}\"\n",
                sdk.version.trim(),
                sdk.path.trim()
            ),
        }),
        (true, _) => knobs.push(Knob {
            id: "apple-sdk-baseline",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: "# disabled: Apple host with no probed SDK baseline\n".to_owned(),
        }),
        (false, _) => knobs.push(Knob {
            id: "apple-sdk-baseline",
            enabled: false,
            benchmark_verdict: BenchmarkVerdict::Ungated,
            fragment: format!("# disabled: {triple} is not an Apple host\n"),
        }),
    }

    // A target-specific rustflags array takes precedence over build.rustflags
    // in Cargo, so ANY knob that opens `[target.<triple>]` would otherwise
    // swallow the threads flag. Mirror it there whenever that section exists.
    if knobs
        .iter()
        .any(|k| k.enabled && k.fragment.contains(&format!("[target.{triple}]")))
        && let Some(knob) = knobs
            .iter_mut()
            .find(|k| k.id == "zthreads-parallel-frontend" && k.enabled)
        && let Some(threads) = evidence.zthreads
    {
        knob.fragment.push_str(&format!(
            "[target.{triple}]\nrustflags = [\"-Zthreads={threads}\"]\n"
        ));
    }

    // cargo-hakari workspace-hack: only when the tool is present.
    knobs.push(Knob {
        id: "hakari-workspace-hack",
        enabled: evidence.hakari_available,
        benchmark_verdict: BenchmarkVerdict::Ungated,
        fragment: if evidence.hakari_available {
            HAKARI_PLAN
                .iter()
                .map(|step| format!("# hakari: {step}\n"))
                .collect()
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
        let mut rustflags: std::collections::BTreeMap<String, Vec<String>> =
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
                } else if let Some(flags) = line
                    .strip_prefix("rustflags = [")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    rustflags
                        .entry(current.clone())
                        .or_default()
                        .push(flags.to_owned());
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
            if let Some(flags) = rustflags.get(section) {
                out.push_str(&format!("rustflags = [{}]\n", flags.join(", ")));
            }
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

    const HOST: &str = "x86_64-unknown-linux-gnu";

    fn evidence(rustc: &str, linkers: &[&str]) -> PackEvidence {
        PackEvidence {
            rustc_version_line: rustc.to_owned(),
            rustc_z_help: Some("    -Z threads=val -- number of compiler threads".to_owned()),
            zthreads: NonZeroU32::new(8),
            line_tables_only: true,
            split_debuginfo_unpacked: true,
            linker_version_lines: linkers.iter().map(|s| (*s).to_owned()).collect(),
            host_target_triple: HOST.to_owned(),
            linker_driver_available: true,
            cranelift_backend_library: None,
            cranelift_dev_backend: false,
            target_cpu_baseline: None,
            apple_deployment_target: None,
            apple_sdk: None,
            sccache_available: true,
            hakari_available: false,
        }
    }

    #[test]
    fn debug_knobs_require_opt_in_and_toggle_independently() {
        let mut e = evidence("rustc 1.100.0 (abc)", &[]);
        for (lines, split) in [(false, false), (true, false), (false, true), (true, true)] {
            e.line_tables_only = lines;
            e.split_debuginfo_unpacked = split;
            let mut pack = assemble(&e);
            let rendered = pack.render_config();
            assert_eq!(rendered.contains("debug = \"line-tables-only\""), lines);
            assert_eq!(rendered.contains("split-debuginfo = \"unpacked\""), split);
            pack.disable("debuginfo-line-tables-only").unwrap();
            assert!(
                !pack
                    .render_config()
                    .contains("debug = \"line-tables-only\"")
            );
            assert_eq!(pack.render_config().contains("split-debuginfo"), split);
        }
    }

    #[test]
    fn b014_zthreads_is_exact_capability_detection_never_unconditional() {
        // Supported nightly: on.
        assert!(matches!(
            detect_zthreads(
                "rustc 1.99.0-nightly (abc 2026-07-01)",
                Some("-Z threads=val -- threads")
            ),
            ZThreadsSupport::Supported { .. }
        ));
        // Stable, beta, malformed nightly, garbage: all typed-unsupported
        // with the evidence echoed.
        for line in [
            "rustc 1.99.0 (abc 2026-07-01)",
            "rustc 1.99.0-beta.2 (abc 2026-07-01)",
            "rustc 1.97.garbage-nightly (abc 2026-05-01)",
            "rustc 1.99.0-nightly-nightly (abc 2026-07-01)",
            "rustc +1.99.0-nightly (abc 2026-07-01)",
            "not rustc at all",
            "",
        ] {
            let ZThreadsSupport::Unsupported { evidence } =
                detect_zthreads(line, Some("-Z threads=val -- threads"))
            else {
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
    fn zthreads_requires_opt_in_and_exact_successful_option_evidence() {
        let mut e = evidence("rustc 1.97.0-nightly (abc 2026-05-01)", &[]);
        // Support is measured, not guessed from a future version cutoff.
        assert!(assemble(&e).render_config().contains("-Zthreads=8"));
        e.zthreads = None;
        assert!(!assemble(&e).render_config().contains("-Zthreads"));
        e.zthreads = NonZeroU32::new(2);
        for help in [
            None,
            Some(""),
            Some("-Z llvm-threads=val"),
            Some("description mentions -Z threads=val"),
            Some("-Z threads-extra=val"),
        ] {
            e.rustc_z_help = help.map(str::to_owned);
            assert!(!assemble(&e).render_config().contains("-Zthreads"));
        }
        e.rustc_z_help = Some("    -Z threads=val -- compiler threads\n".to_owned());
        assert!(assemble(&e).render_config().contains("-Zthreads=2"));
    }

    #[test]
    fn threads_and_linker_flags_share_target_array_without_losing_independent_toggle() {
        let mut pack = assemble(&evidence(
            "rustc 1.100.0-nightly (abc 2026-08-31)",
            &["LLD 18.1.0"],
        ));
        let rendered = pack.render_config();
        assert!(
            rendered.contains("rustflags = [\"-Zthreads=8\", \"-C\", \"link-arg=-fuse-ld=lld\"]")
        );
        pack.disable("zthreads-parallel-frontend").unwrap();
        let disabled = pack.render_config();
        assert!(!disabled.contains("-Zthreads"));
        assert!(disabled.contains("rustflags = [\"-C\", \"link-arg=-fuse-ld=lld\"]"));
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
    fn l0c_linker_selection_needs_a_usable_driver_and_a_known_host() {
        // Detected + driver + ELF host: selected.
        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &["LLD 18.1.0"]);
        assert!(assemble(&e).render_config().contains("-fuse-ld=lld"));

        // Same linker, no clang: the flag cannot be carried, so the pack
        // falls back instead of rendering `linker = "clang"` onto a host
        // that has no clang (which would break EVERY build it touches).
        e.linker_driver_available = false;
        let pack = assemble(&e);
        let system = pack.knobs.iter().find(|k| k.id == "linker-system").unwrap();
        assert!(!system.enabled);
        assert!(system.fragment.contains("clang driver"), "{system:?}");
        assert!(!pack.render_config().contains("linker ="));
        assert!(!pack.render_config().contains("fuse-ld"));

        // Driver back, but a host whose linker spelling this pack does not
        // know: also a fallback, and the rejected triple is named.
        e.linker_driver_available = true;
        e.host_target_triple = "aarch64-apple-darwin".to_owned();
        let pack = assemble(&e);
        let system = pack.knobs.iter().find(|k| k.id == "linker-system").unwrap();
        assert!(!system.enabled);
        assert!(
            system.fragment.contains("aarch64-apple-darwin"),
            "{system:?}"
        );
        assert!(!pack.render_config().contains("fuse-ld"));

        // The three rejections stay distinguishable to an operator.
        let reasons: Vec<String> = [
            LinkerRejection::NotDetected,
            LinkerRejection::DriverMissing {
                candidate: "LLD 18.1.0".to_owned(),
            },
            LinkerRejection::UnsupportedHost {
                triple: HOST.to_owned(),
            },
        ]
        .iter()
        .map(LinkerRejection::explain)
        .collect();
        assert_eq!(
            reasons
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn l0c_target_sections_follow_the_real_host_triple() {
        // A `[target.<triple>]` section written for the WRONG triple is
        // silently inert: the linker knob would claim enabled and change
        // nothing, and the threads flag mirrored into it would vanish.
        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &["wild 0.4.0"]);
        e.host_target_triple = "aarch64-unknown-linux-gnu".to_owned();
        let rendered = assemble(&e).render_config();
        assert!(rendered.contains("[target.aarch64-unknown-linux-gnu]"));
        assert!(!rendered.contains("x86_64-unknown-linux-gnu"));
        // ...and the mirrored threads flag landed in that same section.
        assert!(
            rendered.contains("rustflags = [\"-Zthreads=8\", \"-C\", \"link-arg=--ld-path=wild\"]")
        );
    }

    #[test]
    fn l0e_cranelift_requires_opt_in_nightly_and_an_installed_backend() {
        let backend = "/rustup/.../codegen-backends/librustc_codegen_cranelift.so";
        // Proven only when nightly identity AND the library agree.
        assert!(matches!(
            detect_cranelift("rustc 1.99.0-nightly (abc 2026-07-01)", Some(backend)),
            CraneliftSupport::Supported { .. }
        ));
        // A stable toolchain is never Cranelift-capable here, even when a
        // caller hands over a library path: `codegen-backend` is unstable.
        for (line, lib) in [
            ("rustc 1.99.0 (abc 2026-07-01)", Some(backend)),
            ("rustc 1.99.0-beta.2 (abc 2026-07-01)", Some(backend)),
            ("rustc 1.99.0-nightly (abc 2026-07-01)", None),
            ("rustc 1.99.0-nightly (abc 2026-07-01)", Some("   ")),
            ("not rustc at all", Some(backend)),
        ] {
            assert!(
                matches!(
                    detect_cranelift(line, lib),
                    CraneliftSupport::Unsupported { .. }
                ),
                "{line:?}/{lib:?} must not select an unstable backend"
            );
        }

        // Opt-in and capability are independent gates; both are required.
        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]);
        for (opt_in, lib) in [(false, None), (true, None), (false, Some(backend))] {
            e.cranelift_dev_backend = opt_in;
            e.cranelift_backend_library = lib.map(str::to_owned);
            assert!(!assemble(&e).render_config().contains("cranelift"));
        }
        e.cranelift_dev_backend = true;
        e.cranelift_backend_library = Some(backend.to_owned());
        let mut pack = assemble(&e);
        let rendered = pack.render_config();
        assert!(rendered.contains("codegen-backend = \"cranelift\""));
        // Build scripts and proc macros stay on LLVM: they RUN during the
        // build, and they are the code most likely to need what Cranelift
        // does not implement.
        assert!(rendered.contains("[profile.dev.build-override]"));
        assert!(rendered.contains("codegen-backend = \"llvm\""));
        // ...and it toggles off alone.
        pack.disable("codegen-backend-cranelift").unwrap();
        assert!(!pack.render_config().contains("cranelift"));
        assert!(
            pack.render_config()
                .contains("debug = \"line-tables-only\"")
        );
    }

    #[test]
    fn l0g_target_cpu_is_explicit_and_machine_relative_spellings_are_refused() {
        assert_eq!(resolve_target_cpu(None), TargetCpuDecision::Unset);
        assert_eq!(resolve_target_cpu(Some("  ")), TargetCpuDecision::Unset);
        assert_eq!(
            resolve_target_cpu(Some("x86-64-v3")),
            TargetCpuDecision::Pinned("x86-64-v3".to_owned())
        );
        // `native` resolves to a different cpu on every machine while the
        // rendered pack looks identical — the exact key fragmentation this
        // pack exists to remove.
        for spelling in ["native", "NATIVE", "apple-latest"] {
            assert!(matches!(
                resolve_target_cpu(Some(spelling)),
                TargetCpuDecision::RefusedNonPortable { .. }
            ));
        }

        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]);
        e.target_cpu_baseline = Some("native".to_owned());
        let pack = assemble(&e);
        let knob = pack
            .knobs
            .iter()
            .find(|k| k.id == "target-cpu-baseline")
            .unwrap();
        assert!(!knob.enabled);
        assert!(knob.fragment.contains("refused"), "{knob:?}");
        assert!(!pack.render_config().contains("target-cpu"));

        // Pinned: it lands in the host's target section, and it does NOT
        // swallow the threads flag even though no linker opened that
        // section (target rustflags override build.rustflags in Cargo).
        e.target_cpu_baseline = Some("x86-64-v2".to_owned());
        let rendered = assemble(&e).render_config();
        assert!(rendered.contains(&format!("[target.{HOST}]")));
        assert!(
            rendered.contains("rustflags = [\"-Zthreads=8\", \"-C\", \"target-cpu=x86-64-v2\"]")
        );
    }

    #[test]
    fn l0g_apple_baselines_pin_on_apple_hosts_and_stay_inert_elsewhere() {
        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]);
        e.apple_deployment_target = Some("13.0".to_owned());
        e.apple_sdk = Some(AppleSdkBaseline {
            version: "14.2".to_owned(),
            path: "/Xcode.app/.../MacOSX.sdk".to_owned(),
        });
        // Linux host: both knobs exist in the inventory, both disabled,
        // and nothing reaches the config.
        let rendered = assemble(&e).render_config();
        assert!(!rendered.contains("DEPLOYMENT_TARGET"));
        assert!(!rendered.contains("SDKROOT"));

        e.host_target_triple = "aarch64-apple-darwin".to_owned();
        let rendered = assemble(&e).render_config();
        assert!(rendered.contains("MACOSX_DEPLOYMENT_TARGET = \"13.0\""));
        assert!(rendered.contains("SDKROOT = \"/Xcode.app/.../MacOSX.sdk\""));
        assert!(rendered.contains("# sdk baseline: 14.2"));

        // The deployment variable follows the platform, not the vendor.
        e.host_target_triple = "aarch64-apple-ios".to_owned();
        assert!(
            assemble(&e)
                .render_config()
                .contains("IPHONEOS_DEPLOYMENT_TARGET = \"13.0\"")
        );

        // Apple host with nothing probed: disabled with the reason, not a
        // guessed default.
        e.apple_deployment_target = None;
        e.apple_sdk = None;
        let pack = assemble(&e);
        for id in ["apple-deployment-target", "apple-sdk-baseline"] {
            let knob = pack.knobs.iter().find(|k| k.id == id).unwrap();
            assert!(!knob.enabled);
            assert!(knob.fragment.contains("no "), "{knob:?}");
        }
    }

    #[test]
    fn l0f_hakari_plan_is_fixed_and_ends_in_a_ci_gate() {
        // The sequence is the automation surface: init, generate, manage
        // the dependency edges, then VERIFY — the last step is what a CI
        // lane runs to catch workspace-hack drift.
        assert_eq!(HAKARI_PLAN[0], "cargo hakari init workspace-hack");
        assert_eq!(HAKARI_PLAN[HAKARI_PLAN.len() - 1], "cargo hakari verify");
        let mut e = evidence("rustc 1.99.0-nightly (abc 2026-07-01)", &[]);
        e.hakari_available = true;
        let rendered = assemble(&e).render_config();
        for step in HAKARI_PLAN {
            assert!(rendered.contains(step), "{step} missing from {rendered}");
        }
        // Absent tool: guidance stays out of the config entirely.
        e.hakari_available = false;
        assert!(!assemble(&e).render_config().contains("hakari"));
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
