//! `rch advise` — crate-architecture advice priced by measured compiler time
//! (plan §104; bead Q012; M15).
//!
//! Inputs are real build facts, never fixtures:
//! - `cargo metadata` for the host platform: the resolved package graph,
//!   workspace members and duplicate dependency versions;
//! - Cargo `--timings` reports (`<target-dir>/cargo-timings/*.html`): the
//!   compiler wall time of every unit Cargo actually compiled.
//!
//! The pricing engine is `rabs_key::advise`. This module only measures: it
//! attributes compiler seconds to duplicate versions, feature variants and
//! rebuild tails, and it lists every advice kind it could not measure under
//! `evidence_limits` instead of guessing. Nothing here edits a file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context as _;
use rabs_key::advise::{Advice, AdviceKind, AdviseInputs, advise};
use serde::Deserialize;

use crate::ui::context::OutputContext;
use rch_common::ApiResponse;

/// Arguments for `rch advise`.
#[derive(clap::Args, Debug)]
pub struct AdviseArgs {
    /// Cargo.toml of the package or workspace to analyze (default: ./Cargo.toml)
    #[arg(long, value_name = "PATH")]
    pub manifest_path: Option<PathBuf>,
    /// Cargo timing report to read (`cargo build --timings` HTML). Repeatable.
    /// Default: the newest reports under <target-dir>/cargo-timings/. Reports
    /// of another profile than the first readable one are skipped.
    #[arg(long = "timings", value_name = "HTML")]
    pub timings: Vec<PathBuf>,
    /// Maximum number of discovered timing reports to read, newest first
    #[arg(long, default_value_t = 20)]
    pub max_timings: usize,
    /// Optional RABS CAS root to inspect recorded key fragmentation (read-only)
    #[arg(long, value_name = "DIR")]
    pub cas_root: Option<PathBuf>,
    /// Optional B002 invocation corpus NDJSONL path to measure test wall-time dominance
    #[arg(long, value_name = "PATH")]
    pub corpus: Option<PathBuf>,
}

/// One advice row in its stable wire form.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct AdviceRow {
    /// Stable kind code (never renamed; consumers match on it).
    pub kind: String,
    /// Crate, dependency or binary the advice is about.
    pub subject: String,
    /// Measured facts the advice rests on.
    pub evidence: Vec<String>,
    /// Expected saved compiler latency per affected build (ms).
    pub expected_saved_ms: u64,
    /// Confidence in permille.
    pub confidence_permille: u32,
    /// Whether `expected_saved_ms` is measured compiler time (else an estimate).
    pub measured: bool,
    /// What this advice does not claim.
    pub non_claims: Vec<String>,
}

/// A timing report that was found but not used.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct SkippedReport {
    /// Report path.
    pub path: String,
    /// Why it was not used.
    pub reason: String,
}

/// Summary of live CAS key-fragmentation diagnostics attached via `--cas-root`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct CasFragmentationSummary {
    /// Metadata database inspected (read-only).
    pub metadata_path: String,
    /// Verified actions sampled.
    pub verified_actions: usize,
    /// Sampled actions with incomplete provenance.
    pub incomplete_actions: usize,
    /// Fragmenting canonical components with convergence remediations.
    pub fragmenters: Vec<super::why::FragmentingComponentReport>,
}

/// Summary of B002 invocation corpus test dominance attached via `--corpus`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct CorpusTestSummary {
    /// Corpus path inspected.
    pub corpus_path: String,
    /// Total non-empty lines parsed as valid invocation records.
    pub records_parsed: usize,
    /// Test invocations matched (`Nextest` or `cargo test` / `cargo nextest`).
    pub test_invocations: usize,
    /// Malformed lines skipped (counted honestly).
    pub malformed_lines: usize,
    /// Total observed test wall time across matched invocations (ms).
    pub total_test_wall_ms: u64,
}

/// The complete `rch advise` report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct AdviseReport {
    /// Workspace root reported by Cargo.
    pub workspace_root: String,
    /// Host platform the dependency graph was resolved for, when known.
    pub platform: Option<String>,
    /// Cargo profile whose timings priced the advice.
    pub profile: Option<String>,
    /// Timing reports that contributed units.
    pub timing_reports: Vec<String>,
    /// Timing reports that were found but not used.
    pub skipped_reports: Vec<SkippedReport>,
    /// Distinct compiled units observed across the used reports.
    pub units_observed: usize,
    /// Advice sorted by expected saving (largest first).
    pub advice: Vec<AdviceRow>,
    /// Optional CAS key-fragmentation diagnostics (present when `--cas-root` is given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_fragmentation: Option<CasFragmentationSummary>,
    /// Optional B002 corpus test-dominance summary (present when `--corpus` is given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus_tests: Option<CorpusTestSummary>,
    /// Advice kinds or facts this run could not measure.
    pub evidence_limits: Vec<String>,
}

/// Entry point.
pub fn run(args: &AdviseArgs, ctx: &OutputContext) -> anyhow::Result<()> {
    let manifest = match &args.manifest_path {
        Some(path) => path.clone(),
        None => std::env::current_dir()?.join("Cargo.toml"),
    };
    anyhow::ensure!(
        manifest.is_file(),
        "no Cargo manifest at {}; pass --manifest-path",
        manifest.display()
    );
    let platform = host_platform();
    let metadata = cargo_metadata(&manifest, platform.as_deref())?;
    let reports = if args.timings.is_empty() {
        discover_timing_reports(
            &metadata.target_directory.join("cargo-timings"),
            args.max_timings,
        )
    } else {
        args.timings.clone()
    };
    let report = build_report_with_sources(
        &metadata,
        platform,
        &reports,
        args.cas_root.as_deref(),
        args.corpus.as_deref(),
    )?;
    if ctx.is_json() {
        ctx.json(&ApiResponse::ok("advise", &report))?;
    } else {
        println!("{}", format_report(&report));
    }
    Ok(())
}

// -- cargo metadata ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    resolve: Option<Resolve>,
    target_directory: PathBuf,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    targets: Vec<MetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    #[serde(default)]
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Resolve {
    nodes: Vec<ResolveNode>,
}

#[derive(Debug, Deserialize)]
struct ResolveNode {
    id: String,
    #[serde(default)]
    deps: Vec<ResolveDep>,
}

#[derive(Debug, Deserialize)]
struct ResolveDep {
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<DepKind>,
}

#[derive(Debug, Deserialize)]
struct DepKind {
    kind: Option<String>,
}

fn host_platform() -> Option<String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_owned())
}

pub(crate) fn cargo_metadata(manifest: &Path, platform: Option<&str>) -> anyhow::Result<Metadata> {
    let output = metadata_command(manifest, platform)?
        .output()
        .context("cannot run cargo metadata")?;
    anyhow::ensure!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    serde_json::from_slice(&output.stdout).context("cargo metadata output was not understood")
}

/// Cargo runs from the manifest's directory, so a workspace
/// rust-toolchain.toml selects the toolchain it resolves with. The manifest
/// path is therefore made absolute first: relative to our own working
/// directory, `sub/Cargo.toml` would otherwise be read as `sub/sub/...`.
fn metadata_command(manifest: &Path, platform: Option<&str>) -> anyhow::Result<Command> {
    let manifest = std::path::absolute(manifest)
        .with_context(|| format!("cannot resolve {}", manifest.display()))?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(&manifest);
    if let Some(platform) = platform {
        command.args(["--filter-platform", platform]);
    }
    if let Some(parent) = manifest.parent().filter(|parent| parent.is_dir()) {
        command.current_dir(parent);
    }
    Ok(command)
}

// -- timing reports ---------------------------------------------------------------

/// One compiled unit as Cargo's timing report records it.
#[derive(Debug, Clone, Deserialize)]
struct TimedUnit {
    name: String,
    version: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    features: Vec<String>,
    duration: f64,
    #[serde(default)]
    sections: Option<Vec<(String, Section)>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct Section {
    start: f64,
    end: f64,
}

#[derive(Debug, Clone)]
struct TimingReport {
    profile: Option<String>,
    units: Vec<TimedUnit>,
}

const UNIT_DATA_MARKER: &str = "const UNIT_DATA = ";

fn parse_timing_report(html: &str) -> Result<TimingReport, String> {
    let start = html
        .find(UNIT_DATA_MARKER)
        .ok_or("no UNIT_DATA table (not a Cargo timing report)")?
        + UNIT_DATA_MARKER.len();
    let units = serde_json::Deserializer::from_str(&html[start..])
        .into_iter::<Vec<TimedUnit>>()
        .next()
        .ok_or("empty UNIT_DATA table")?
        .map_err(|error| format!("UNIT_DATA is not understood: {error}"))?;
    if let Some(unit) = units
        .iter()
        .find(|unit| !unit.duration.is_finite() || unit.duration < 0.0)
    {
        return Err(format!("unit {} has an invalid duration", unit.name));
    }
    let profile = html
        .split_once("<td>Profile:</td><td>")
        .and_then(|(_, rest)| rest.split_once("</td>"))
        .map(|(profile, _)| profile.trim().to_owned())
        .filter(|profile| !profile.is_empty());
    Ok(TimingReport { profile, units })
}

/// Newest first: Cargo names each report `cargo-timing-<UTC timestamp>-<hash>.html`.
/// The `cargo-timing.html` alias duplicates the newest report and is skipped.
fn discover_timing_reports(directory: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut reports: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("cargo-timing-") && name.ends_with(".html"))
        })
        .collect();
    reports.sort();
    reports.reverse();
    reports.truncate(limit);
    reports
}

fn ms(seconds: f64) -> u64 {
    // Durations are validated finite and non-negative; reports carry seconds
    // with two decimals, so the rounded value is exact at ms resolution.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let value = (seconds * 1000.0).round() as u64;
    value
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

/// One unit identity across reports: the same compile of the same crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnitKey {
    name: String,
    version: String,
    target: String,
    features: Vec<String>,
}

/// Median compiler time per unit identity, plus link time where reported.
#[derive(Debug, Default)]
struct UnitTimes {
    duration_ms: BTreeMap<UnitKey, u64>,
    link_ms: BTreeMap<UnitKey, u64>,
}

impl UnitTimes {
    fn from_reports(reports: &[TimingReport]) -> Self {
        let mut durations: BTreeMap<UnitKey, Vec<u64>> = BTreeMap::new();
        let mut links: BTreeMap<UnitKey, Vec<u64>> = BTreeMap::new();
        for report in reports {
            for unit in &report.units {
                let mut features = unit.features.clone();
                features.sort();
                let key = UnitKey {
                    name: unit.name.clone(),
                    version: unit.version.clone(),
                    target: unit.target.trim().to_owned(),
                    features,
                };
                durations
                    .entry(key.clone())
                    .or_default()
                    .push(ms(unit.duration));
                let link = unit.sections.iter().flatten().find_map(|(name, section)| {
                    (name == "link" && section.end >= section.start)
                        .then(|| ms(section.end - section.start))
                });
                if let Some(link) = link {
                    links.entry(key).or_default().push(link);
                }
            }
        }
        Self {
            duration_ms: durations
                .into_iter()
                .map(|(key, mut values)| (key, median(&mut values)))
                .collect(),
            link_ms: links
                .into_iter()
                .map(|(key, mut values)| (key, median(&mut values)))
                .collect(),
        }
    }

    /// One compile of every target of a package version. A target built under
    /// several feature sets counts once, at its most expensive variant: the
    /// extra variants are priced by feature advice and must not inflate a
    /// rebuild tail or a version's cost.
    fn package_ms(&self, name: &str, version: &str) -> Option<u64> {
        let mut per_target: BTreeMap<&str, u64> = BTreeMap::new();
        for (key, ms) in &self.duration_ms {
            if key.name == name && key.version == version {
                let slot = per_target.entry(key.target.as_str()).or_default();
                *slot = (*slot).max(*ms);
            }
        }
        (!per_target.is_empty()).then(|| saturating_sum(per_target.into_values()))
    }
}

/// Report durations are untrusted input; never overflow on a corrupt one.
fn saturating_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values.into_iter().fold(0, u64::saturating_add)
}

/// A unit that compiles the library crate itself (`""`, or `lib (check)` etc.).
fn is_library_unit(target: &str) -> bool {
    target.is_empty() || target == "lib" || target.starts_with("lib (")
}

// -- attribution ------------------------------------------------------------------

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let (release, pre) = match version.split_once(['-', '+']) {
            Some((release, _)) => (release, true),
            None => (version, false),
        };
        (
            release
                .split('.')
                .map(|part| part.parse().unwrap_or(0))
                .collect(),
            pre,
        )
    };
    let (left_numbers, left_pre) = parts(left);
    let (right_numbers, right_pre) = parts(right);
    left_numbers
        .cmp(&right_numbers)
        // A pre-release precedes its release.
        .then_with(|| right_pre.cmp(&left_pre))
        .then_with(|| left.cmp(right))
}

struct Attribution {
    inputs: AdviseInputs,
    extra_evidence: BTreeMap<(AdviceKindCode, String), Vec<String>>,
    limits: Vec<String>,
}

type AdviceKindCode = &'static str;

const fn kind_code(kind: AdviceKind) -> AdviceKindCode {
    match kind {
        AdviceKind::SplitRebuildTailCrate => "split_rebuild_tail_crate",
        AdviceKind::ReduceFeatureCoupling => "reduce_feature_coupling",
        AdviceKind::IsolateProcMacro => "isolate_proc_macro",
        AdviceKind::AlignVersions => "align_versions",
        AdviceKind::LinkBottleneck => "link_bottleneck",
        AdviceKind::DominatingTests => "dominating_tests",
    }
}

#[allow(clippy::too_many_lines)]
fn attribute(metadata: &Metadata, times: &UnitTimes, timed: bool) -> Attribution {
    let mut inputs = AdviseInputs::default();
    let mut extra_evidence: BTreeMap<(AdviceKindCode, String), Vec<String>> = BTreeMap::new();
    let mut limits = Vec::new();
    let packages: BTreeMap<&str, &MetadataPackage> = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    let nodes: Vec<&ResolveNode> = metadata
        .resolve
        .as_ref()
        .map(|resolve| resolve.nodes.iter().collect())
        .unwrap_or_default();
    if nodes.is_empty() {
        limits.push("dependency graph: cargo metadata returned no resolve graph".to_owned());
    }

    // Duplicate versions in the resolved (host-filtered) graph.
    let mut versions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for node in &nodes {
        if let Some(package) = packages.get(node.id.as_str()) {
            versions
                .entry(package.name.as_str())
                .or_default()
                .insert(package.version.as_str());
        }
    }
    for (name, set) in &versions {
        if set.len() < 2 {
            continue;
        }
        let mut ordered: Vec<&str> = set.iter().copied().collect();
        ordered.sort_by(|left, right| compare_versions(left, right));
        let newest = ordered[ordered.len() - 1];
        let older = &ordered[..ordered.len() - 1];
        let measured = if timed {
            older
                .iter()
                .map(|version| times.package_ms(name, version))
                .collect::<Option<Vec<u64>>>()
                .map(saturating_sum)
        } else {
            None
        };
        let mut evidence = vec![format!("versions: {}", ordered.join(", "))];
        if measured.is_some() {
            evidence.push(format!(
                "converging on {newest} removes the compiles of {}",
                older.join(", ")
            ));
        } else if timed {
            evidence.push(
                "not priced: a timing report lacks a compile of one of the older versions"
                    .to_owned(),
            );
        }
        extra_evidence.insert(
            (kind_code(AdviceKind::AlignVersions), (*name).to_owned()),
            evidence,
        );
        inputs.version_spread.push((
            (*name).to_owned(),
            u32::try_from(set.len()).unwrap_or(u32::MAX),
            measured,
        ));
    }

    if timed {
        // Feature variants: one library compiled under several feature sets.
        let mut variants: BTreeMap<(&str, &str, &str), Vec<u64>> = BTreeMap::new();
        for (key, duration) in &times.duration_ms {
            if is_library_unit(&key.target) {
                variants
                    .entry((&key.name, &key.version, &key.target))
                    .or_default()
                    .push(*duration);
            }
        }
        let mut per_crate: BTreeMap<&str, (u32, u64)> = BTreeMap::new();
        for ((name, _, _), durations) in &variants {
            if durations.len() < 2 {
                continue;
            }
            let total = saturating_sum(durations.iter().copied());
            let kept = durations.iter().copied().max().unwrap_or(0);
            let entry = per_crate.entry(*name).or_default();
            if u32::try_from(durations.len()).unwrap_or(u32::MAX) > entry.0 {
                *entry = (
                    u32::try_from(durations.len()).unwrap_or(u32::MAX),
                    total - kept,
                );
            }
        }
        for (name, (count, extra)) in per_crate {
            inputs
                .feature_variants
                .push((name.to_owned(), count, Some(extra)));
        }

        // Rebuild tails of workspace libraries over normal/build dependents.
        let mut dependents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for node in &nodes {
            for dep in &node.deps {
                let rebuilds = dep.dep_kinds.is_empty()
                    || dep
                        .dep_kinds
                        .iter()
                        .any(|kind| kind.kind.as_deref() != Some("dev"));
                if rebuilds {
                    dependents
                        .entry(dep.pkg.as_str())
                        .or_default()
                        .insert(node.id.as_str());
                }
            }
        }
        let cost = |id: &str| -> Option<u64> {
            packages
                .get(id)
                .and_then(|package| times.package_ms(&package.name, &package.version))
        };
        let mut memo: BTreeMap<&str, u64> = BTreeMap::new();
        let mut untimed_dependents: BTreeSet<&str> = BTreeSet::new();
        for member in &metadata.workspace_members {
            let Some(package) = packages.get(member.as_str()) else {
                continue;
            };
            let is_library = package.targets.iter().any(|target| {
                target
                    .kind
                    .iter()
                    .any(|kind| matches!(kind.as_str(), "lib" | "rlib" | "proc-macro"))
            });
            if !is_library || cost(member).is_none() {
                continue;
            }
            let mut closure = BTreeSet::new();
            let mut stack = vec![member.as_str()];
            while let Some(id) = stack.pop() {
                for dependent in dependents.get(id).into_iter().flatten() {
                    if closure.insert(*dependent) {
                        stack.push(dependent);
                    }
                }
            }
            if closure.is_empty() {
                continue;
            }
            untimed_dependents.extend(closure.iter().filter(|id| cost(id).is_none()));
            let tail = critical_path(member, &dependents, &cost, &mut memo);
            let sum = saturating_sum(closure.iter().filter_map(|id| cost(id)).chain(cost(member)));
            extra_evidence.insert(
                (
                    kind_code(AdviceKind::SplitRebuildTailCrate),
                    package.name.clone(),
                ),
                vec![format!(
                    "the tail is the longest chain of measured crate compile times through its \
                     normal/build dependents; their compiles total {sum}ms"
                )],
            );
            inputs.rebuild_tails.push((
                package.name.clone(),
                tail,
                u32::try_from(closure.len()).unwrap_or(u32::MAX),
            ));
        }
        if !untimed_dependents.is_empty() {
            limits.push(format!(
                "rebuild tails: {} dependent crates had no compile in the timing reports and \
                 count as 0ms",
                untimed_dependents.len()
            ));
        }

        // Link time, where the report carries per-section timings.
        if times.link_ms.is_empty() {
            limits.push(
                "link time: the timing reports carry no `link` section (needs a Cargo with \
                 section timings); link bottlenecks are not measured"
                    .to_owned(),
            );
        }
        for (key, link) in &times.link_ms {
            inputs.link_ms.push((
                format!("{} {}", key.name, key.target).trim().to_owned(),
                *link,
            ));
        }
    } else {
        limits.push(
            "timings: no Cargo timing report was read; savings are estimates, and rebuild tails, \
             feature variants and link time are not measured (run `cargo build --timings`)"
                .to_owned(),
        );
    }
    limits.push(
        "proc-macro rebuilds: no rebuild-history source is wired; isolate-proc-macro advice is \
         not measured"
            .to_owned(),
    );
    limits.push(
        "test dominance: timing reports carry compile time, not test run time; dominating-test \
         advice is not measured"
            .to_owned(),
    );
    Attribution {
        inputs,
        extra_evidence,
        limits,
    }
}

/// Longest measured chain from `id` through its dependents (wall-clock lower
/// bound of an edit's rebuild with unbounded parallelism and no pipelining).
fn critical_path<'a>(
    id: &'a str,
    dependents: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    cost: &dyn Fn(&str) -> Option<u64>,
    memo: &mut BTreeMap<&'a str, u64>,
) -> u64 {
    if let Some(known) = memo.get(id) {
        return *known;
    }
    let below = dependents
        .get(id)
        .into_iter()
        .flatten()
        .map(|dependent| critical_path(dependent, dependents, cost, memo))
        .max()
        .unwrap_or(0);
    let total = cost(id).unwrap_or(0).saturating_add(below);
    memo.insert(id, total);
    total
}

struct CorpusTestAnalysis {
    summary: CorpusTestSummary,
    dominance: Vec<(String, u32)>,
    extra_evidence: BTreeMap<(AdviceKindCode, String), Vec<String>>,
}

fn is_test_invocation(tool: &str, command: &str) -> bool {
    if tool == "Nextest" {
        return true;
    }
    if tool != "CargoWholeCommand" {
        return false;
    }
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let Some(cargo_pos) = tokens.iter().position(|t| *t == "cargo") else {
        return false;
    };
    for token in tokens.iter().skip(cargo_pos + 1) {
        if token.starts_with('+') || token.starts_with('-') {
            continue;
        }
        return matches!(*token, "test" | "t" | "nextest");
    }
    false
}

fn suite_label_from_record(cwd: &str, command: &str) -> String {
    let repo = Path::new(cwd)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(cwd);
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut index = 0;
    while index < tokens.len() {
        if matches!(tokens[index], "-p" | "--package" | "--test")
            && let Some(target) = tokens.get(index + 1)
            && !target.starts_with('-')
        {
            return format!("{repo}::{target}");
        }
        index += 1;
    }
    repo.to_owned()
}

fn analyze_corpus_tests(path: &Path) -> anyhow::Result<CorpusTestAnalysis> {
    use std::io::{BufRead as _, BufReader};

    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open B002 corpus {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records_parsed = 0_usize;
    let mut test_invocations = 0_usize;
    let mut malformed_lines = 0_usize;
    let mut per_suite_ms: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    let mut total_test_wall_ms = 0_u64;

    for line in reader.lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            malformed_lines += 1;
            continue;
        };
        let (Some(tool), Some(cwd), Some(duration_ms), Some(argv)) = (
            value.get("tool").and_then(serde_json::Value::as_str),
            value
                .get("cwd_redacted")
                .and_then(serde_json::Value::as_str),
            value.get("duration_ms").and_then(serde_json::Value::as_u64),
            value
                .get("argv_redacted")
                .and_then(serde_json::Value::as_array),
        ) else {
            malformed_lines += 1;
            continue;
        };
        records_parsed += 1;
        let command = argv
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        if !is_test_invocation(tool, &command) {
            continue;
        }
        test_invocations += 1;
        total_test_wall_ms = total_test_wall_ms.saturating_add(duration_ms);
        let suite = suite_label_from_record(cwd, &command);
        let entry = per_suite_ms.entry(suite).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(duration_ms);
        entry.1 += 1;
    }

    let mut dominance = Vec::new();
    let mut extra_evidence = BTreeMap::new();
    if total_test_wall_ms > 0 {
        for (suite, (suite_ms, count)) in per_suite_ms {
            let permille = u32::try_from(
                suite_ms
                    .saturating_mul(1_000)
                    .checked_div(total_test_wall_ms)
                    .unwrap_or(0)
                    .min(1_000),
            )
            .unwrap_or(1_000);
            extra_evidence.insert(
                (kind_code(AdviceKind::DominatingTests), suite.clone()),
                vec![format!(
                    "measured from corpus: {count} test invocation(s) totaling {suite_ms}ms out of {total_test_wall_ms}ms test wall time"
                )],
            );
            dominance.push((suite, permille));
        }
    }

    Ok(CorpusTestAnalysis {
        summary: CorpusTestSummary {
            corpus_path: path.display().to_string(),
            records_parsed,
            test_invocations,
            malformed_lines,
            total_test_wall_ms,
        },
        dominance,
        extra_evidence,
    })
}

#[cfg(test)]
fn build_report(
    metadata: &Metadata,
    platform: Option<String>,
    reports: &[PathBuf],
) -> AdviseReport {
    build_report_with_sources(metadata, platform, reports, None, None)
        .expect("build_report without external CAS/corpus sources is infallible")
}

fn build_report_with_sources(
    metadata: &Metadata,
    platform: Option<String>,
    reports: &[PathBuf],
    cas_root: Option<&Path>,
    corpus_path: Option<&Path>,
) -> anyhow::Result<AdviseReport> {
    let mut skipped = Vec::new();
    let mut parsed = Vec::new();
    for path in reports {
        match std::fs::read_to_string(path)
            .map_err(|error| error.to_string())
            .and_then(|html| parse_timing_report(&html))
        {
            Ok(report) => parsed.push((path.clone(), report)),
            Err(reason) => skipped.push(SkippedReport {
                path: path.display().to_string(),
                reason,
            }),
        }
    }
    // Price with one profile: the first readable report's. Discovery lists
    // reports newest first; explicit --timings keep the order given.
    let profile = parsed
        .first()
        .and_then(|(_, report)| report.profile.clone());
    let mut used = Vec::new();
    let mut timing_reports = Vec::new();
    for (path, report) in parsed {
        if report.profile == profile {
            timing_reports.push(path.display().to_string());
            used.push(report);
        } else {
            skipped.push(SkippedReport {
                path: path.display().to_string(),
                reason: format!(
                    "profile {} differs from the analyzed profile",
                    report.profile.as_deref().unwrap_or("unknown")
                ),
            });
        }
    }
    let times = UnitTimes::from_reports(&used);
    let mut attribution = attribute(metadata, &times, !used.is_empty());

    let mut cas_fragmentation = None;
    if let Some(root) = cas_root {
        let frag = super::why::explain_fragmentation(root, 500)?;
        if frag.verified_actions < 2 {
            attribution.limits.push(format!(
                "CAS fragmentation: {} verified breakdown(s) at {}; need >= 2 verified actions to rank key fragmenters",
                frag.verified_actions, frag.metadata_path
            ));
        }
        cas_fragmentation = Some(CasFragmentationSummary {
            metadata_path: frag.metadata_path,
            verified_actions: frag.verified_actions,
            incomplete_actions: frag.incomplete_actions,
            fragmenters: frag.fragmenters,
        });
    }

    let mut corpus_tests = None;
    if let Some(corpus) = corpus_path {
        let analysis = analyze_corpus_tests(corpus)?;
        if analysis.summary.test_invocations > 0 {
            attribution
                .limits
                .retain(|limit| !limit.starts_with("test dominance:"));
            attribution.inputs.test_dominance = analysis.dominance;
            attribution.extra_evidence.extend(analysis.extra_evidence);
            if analysis.summary.malformed_lines > 0 {
                attribution.limits.push(format!(
                    "corpus: skipped {} malformed line(s) while reading {}",
                    analysis.summary.malformed_lines, analysis.summary.corpus_path
                ));
            }
        } else {
            attribution.limits.push(format!(
                "corpus: {} had {} parsed record(s) but 0 test invocations",
                analysis.summary.corpus_path, analysis.summary.records_parsed
            ));
        }
        corpus_tests = Some(analysis.summary);
    }

    let advice = advise(&attribution.inputs)
        .into_iter()
        .map(|advice| row(advice, &attribution.extra_evidence))
        .collect();
    let mut evidence_limits = attribution.limits;
    if platform.is_none() {
        evidence_limits.push(
            "platform: rustc -vV was unavailable, so the dependency graph includes every \
             platform's dependencies"
                .to_owned(),
        );
    }
    Ok(AdviseReport {
        workspace_root: metadata.workspace_root.display().to_string(),
        platform,
        profile,
        timing_reports,
        skipped_reports: skipped,
        units_observed: times.duration_ms.len(),
        advice,
        cas_fragmentation,
        corpus_tests,
        evidence_limits,
    })
}

fn row(advice: Advice, extra: &BTreeMap<(AdviceKindCode, String), Vec<String>>) -> AdviceRow {
    let kind = kind_code(advice.kind);
    // Only a duplicate-compile price is itself measured compiler time. A
    // rebuild tail or link time is measured, but the saving the engine
    // derives from it (a split halves it) is still an estimate.
    let measured = advice
        .non_claims
        .iter()
        .any(|claim| claim.starts_with("NO_CLAIM_INCREMENTAL_SAVINGS"));
    let mut evidence = advice.evidence;
    if let Some(lines) = extra.get(&(kind, advice.subject.clone())) {
        evidence.extend(lines.iter().cloned());
    }
    AdviceRow {
        kind: kind.to_owned(),
        subject: advice.subject,
        evidence,
        expected_saved_ms: advice.expected_saved_ms,
        confidence_permille: advice.confidence_permille,
        measured,
        non_claims: advice.non_claims.into_iter().map(str::to_owned).collect(),
    }
}

fn format_report(report: &AdviseReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "rch advise: {}", report.workspace_root);
    let _ = writeln!(
        out,
        "  timing reports: {} used ({} units, profile {}), {} skipped",
        report.timing_reports.len(),
        report.units_observed,
        report.profile.as_deref().unwrap_or("-"),
        report.skipped_reports.len()
    );
    if report.advice.is_empty() {
        let _ = writeln!(
            out,
            "\nNo advice: every measured input is below its threshold."
        );
    }
    for (index, row) in report.advice.iter().enumerate() {
        let _ = writeln!(
            out,
            "\n{}. {} `{}` — saves ~{}ms per affected build ({}, confidence {}‰)",
            index + 1,
            row.kind,
            row.subject,
            row.expected_saved_ms,
            if row.measured { "measured" } else { "estimate" },
            row.confidence_permille
        );
        for line in &row.evidence {
            let _ = writeln!(out, "   - {line}");
        }
    }
    if let Some(frag) = &report.cas_fragmentation {
        let _ = writeln!(
            out,
            "\nCAS key fragmentation ({}, {} verified, {} incomplete):",
            frag.metadata_path, frag.verified_actions, frag.incomplete_actions
        );
        if frag.fragmenters.is_empty() {
            let _ = writeln!(out, "  - no fragmenting key components observed");
        } else {
            for item in &frag.fragmenters {
                let _ = writeln!(
                    out,
                    "  - `{}`: {} distinct values across {} actions [{}] -> {}",
                    item.component,
                    item.distinct_values,
                    item.observations,
                    item.category,
                    item.remediation
                );
            }
        }
    }
    if let Some(corpus) = &report.corpus_tests {
        let _ = writeln!(
            out,
            "\nCorpus test timing ({}): {} records parsed, {} test invocations ({}ms total, {} malformed)",
            corpus.corpus_path,
            corpus.records_parsed,
            corpus.test_invocations,
            corpus.total_test_wall_ms,
            corpus.malformed_lines
        );
    }
    if !report.evidence_limits.is_empty() {
        let _ = writeln!(out, "\nEvidence limits:");
        for limit in &report.evidence_limits {
            let _ = writeln!(out, "  - {limit}");
        }
    }
    let _ = write!(out, "\nrch never edits source or config.");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a real `cargo build --timings` report (cargo 1.97.0).
    const REAL_REPORT: &str = r#"<table>
<tr><td>Profile:</td><td>dev</td></tr>
</table>
<script>
const UNIT_DATA = [
  {"i": 1, "name": "itoa", "version": "1.0.18", "mode": "todo", "target": "",
   "features": [], "start": 0.19, "duration": 0.29,
   "unblocked_units": [], "unblocked_rmeta_units": [],
   "sections": [["frontend", {"start": 0.0, "end": 0.23}], ["codegen", {"start": 0.23, "end": 0.29}]]},
  {"i": 2, "name": "memchr", "version": "2.8.3", "mode": "todo", "target": "",
   "features": ["alloc", "default", "std"], "start": 0.48, "duration": 0.72,
   "unblocked_units": [0], "unblocked_rmeta_units": [],
   "sections": [["frontend", {"start": 0.0, "end": 0.45}], ["codegen", {"start": 0.45, "end": 0.72}]]},
  {"i": 0, "name": "advprobe", "version": "0.1.0", "mode": "todo", "target": " advprobe \"bin\"",
   "features": [], "start": 1.2, "duration": 0.23,
   "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null}
];
const CONCURRENCY_DATA = [];
</script>"#;

    fn report(profile: &str, units: &[(&str, &str, &str, &[&str], f64)]) -> TimingReport {
        TimingReport {
            profile: Some(profile.to_owned()),
            units: units
                .iter()
                .map(|(name, version, target, features, duration)| TimedUnit {
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                    target: (*target).to_owned(),
                    features: features.iter().map(|f| (*f).to_owned()).collect(),
                    duration: *duration,
                    sections: None,
                })
                .collect(),
        }
    }

    fn metadata(json: serde_json::Value) -> Metadata {
        serde_json::from_value(json).unwrap()
    }

    fn package(id: &str, name: &str, version: &str, kind: &str) -> serde_json::Value {
        serde_json::json!({"id": id, "name": name, "version": version,
            "targets": [{"kind": [kind]}]})
    }

    #[test]
    fn a_real_cargo_timing_report_parses_with_profile_and_sections() {
        let parsed = parse_timing_report(REAL_REPORT).unwrap();
        assert_eq!(parsed.profile.as_deref(), Some("dev"));
        assert_eq!(parsed.units.len(), 3);
        let times = UnitTimes::from_reports(&[parsed]);
        assert_eq!(times.package_ms("memchr", "2.8.3"), Some(720));
        assert_eq!(times.package_ms("advprobe", "0.1.0"), Some(230));
        assert_eq!(times.package_ms("memchr", "9.9.9"), None);
        // frontend/codegen sections are not link time.
        assert!(times.link_ms.is_empty());
    }

    #[test]
    fn malformed_reports_are_refused_with_a_reason() {
        assert!(parse_timing_report("<html>no table</html>").is_err());
        assert!(parse_timing_report("const UNIT_DATA = [{\"name\": 1}];").is_err());
        let negative = r#"const UNIT_DATA = [{"name":"a","version":"1","duration":-1.0}];"#;
        assert!(
            parse_timing_report(negative)
                .unwrap_err()
                .contains("invalid duration")
        );
    }

    #[test]
    fn link_sections_are_measured_when_cargo_reports_them() {
        let html = r#"const UNIT_DATA = [{"name":"app","version":"0.1.0","target":" app \"bin\"",
            "features":[],"duration":12.5,
            "sections":[["frontend",{"start":0.0,"end":1.0}],["link",{"start":1.5,"end":12.4}]]}];"#;
        let times = UnitTimes::from_reports(&[parse_timing_report(html).unwrap()]);
        assert_eq!(
            times.link_ms.values().copied().collect::<Vec<_>>(),
            [10_900]
        );
    }

    #[test]
    fn version_ordering_follows_release_numbers() {
        let mut versions = vec!["1.10.0", "1.9.3", "2.0.0-rc.1", "2.0.0", "0.3.1"];
        versions.sort_by(|left, right| compare_versions(left, right));
        assert_eq!(
            versions,
            ["0.3.1", "1.9.3", "1.10.0", "2.0.0-rc.1", "2.0.0"]
        );
    }

    #[test]
    fn duplicate_versions_are_priced_by_the_older_versions_compiles() {
        let meta = metadata(serde_json::json!({
            "packages": [
                package("app", "app", "0.1.0", "bin"),
                package("syn1", "syn", "1.0.109", "lib"),
                package("syn2", "syn", "2.0.90", "lib"),
            ],
            "workspace_members": ["app"],
            "resolve": {"nodes": [
                {"id": "app", "deps": [{"pkg": "syn1", "dep_kinds": [{"kind": null}]},
                                       {"pkg": "syn2", "dep_kinds": [{"kind": null}]}]},
                {"id": "syn1", "deps": []},
                {"id": "syn2", "deps": []},
            ]},
            "target_directory": "/t", "workspace_root": "/w",
        }));
        let reports = [report(
            "dev",
            &[
                ("syn", "1.0.109", "", &["full"], 4.2),
                ("syn", "1.0.109", "build script", &[], 0.3),
                ("syn", "2.0.90", "", &["full"], 6.0),
                ("app", "0.1.0", "app \"bin\"", &[], 1.0),
            ],
        )];
        let times = UnitTimes::from_reports(&reports);
        let attribution = attribute(&meta, &times, true);
        assert_eq!(
            attribution.inputs.version_spread,
            vec![("syn".to_owned(), 2, Some(4_500))]
        );
        // Without timings the same graph is reported, unpriced.
        let unpriced = attribute(&meta, &UnitTimes::default(), false);
        assert_eq!(
            unpriced.inputs.version_spread,
            vec![("syn".to_owned(), 2, None)]
        );
        assert!(
            unpriced
                .limits
                .iter()
                .any(|limit| limit.starts_with("timings:"))
        );
    }

    #[test]
    fn feature_variants_across_reports_price_every_variant_but_one() {
        let meta = metadata(serde_json::json!({
            "packages": [package("common", "common", "0.1.0", "lib")],
            "workspace_members": ["common"],
            "resolve": {"nodes": [{"id": "common", "deps": []}]},
            "target_directory": "/t", "workspace_root": "/w",
        }));
        let reports = [
            report("dev", &[("common", "0.1.0", "", &["a"], 1.0)]),
            report("dev", &[("common", "0.1.0", "", &["b"], 2.0)]),
            report("dev", &[("common", "0.1.0", "", &["a", "b"], 3.0)]),
            // The same variant again is the same unit, not a new variant.
            report("dev", &[("common", "0.1.0", "", &["b"], 2.2)]),
        ];
        let times = UnitTimes::from_reports(&reports);
        let attribution = attribute(&meta, &times, true);
        assert_eq!(
            attribution.inputs.feature_variants,
            vec![("common".to_owned(), 3, Some(3_200))]
        );
    }

    #[test]
    fn rebuild_tails_follow_the_longest_measured_dependent_chain() {
        // core <- mid <- app, core <- leaf; tests (dev edge) do not count.
        let meta = metadata(serde_json::json!({
            "packages": [
                package("core", "core", "0.1.0", "lib"),
                package("mid", "mid", "0.1.0", "lib"),
                package("leaf", "leaf", "0.1.0", "lib"),
                package("app", "app", "0.1.0", "bin"),
                package("tests", "tests", "0.1.0", "lib"),
            ],
            "workspace_members": ["core", "mid", "leaf", "app", "tests"],
            "resolve": {"nodes": [
                {"id": "core", "deps": [{"pkg": "tests", "dep_kinds": [{"kind": "dev"}]}]},
                {"id": "mid", "deps": [{"pkg": "core", "dep_kinds": [{"kind": null}]}]},
                {"id": "leaf", "deps": [{"pkg": "core", "dep_kinds": [{"kind": "build"}]}]},
                {"id": "app", "deps": [{"pkg": "mid", "dep_kinds": [{"kind": null}]}]},
                {"id": "tests", "deps": [{"pkg": "core", "dep_kinds": [{"kind": null}]}]},
            ]},
            "target_directory": "/t", "workspace_root": "/w",
        }));
        let reports = [report(
            "dev",
            &[
                ("core", "0.1.0", "", &[], 2.0),
                ("mid", "0.1.0", "", &[], 3.0),
                ("leaf", "0.1.0", "", &[], 1.0),
                ("app", "0.1.0", "app \"bin\"", &[], 4.0),
            ],
        )];
        let times = UnitTimes::from_reports(&reports);
        let attribution = attribute(&meta, &times, true);
        let tails: BTreeMap<_, _> = attribution
            .inputs
            .rebuild_tails
            .iter()
            .map(|(name, tail, dependents)| (name.as_str(), (*tail, *dependents)))
            .collect();
        // core -> mid -> app = 2 + 3 + 4 s; dependents mid, leaf, app, tests.
        assert_eq!(tails["core"], (9_000, 4));
        assert_eq!(tails["mid"], (7_000, 1));
        // leaf and app have no dependents; tests has no timing at all.
        assert!(!tails.contains_key("leaf") && !tails.contains_key("app"));
        assert!(
            attribution
                .limits
                .iter()
                .any(|limit| limit.starts_with("rebuild tails: 1 dependent"))
        );
    }

    #[test]
    fn metadata_runs_in_the_manifest_directory_with_an_absolute_manifest_path() {
        // Test binaries run from their package directory, where src/ exists.
        let command = metadata_command(
            Path::new("src/Cargo.toml"),
            Some("x86_64-unknown-linux-gnu"),
        )
        .unwrap();
        let args: Vec<_> = command.get_args().collect();
        let at = args
            .iter()
            .position(|arg| *arg == "--manifest-path")
            .unwrap();
        let manifest = Path::new(args[at + 1]);
        assert_eq!(
            manifest,
            std::env::current_dir().unwrap().join("src/Cargo.toml")
        );
        assert_eq!(command.get_current_dir(), manifest.parent());
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--filter-platform", "x86_64-unknown-linux-gnu"])
        );
    }

    #[test]
    fn a_feature_split_counts_one_compile_per_target_in_package_cost() {
        // `core` was built under two feature sets across reports: its rebuild
        // tail and version cost use one compile (the most expensive variant)
        // per target, never the sum of the variants.
        let reports = [
            report(
                "dev",
                &[
                    ("core", "0.1.0", "", &["a"], 2.0),
                    ("core", "0.1.0", "build script", &[], 0.5),
                ],
            ),
            report("dev", &[("core", "0.1.0", "", &["a", "b"], 5.0)]),
        ];
        let times = UnitTimes::from_reports(&reports);
        assert_eq!(times.package_ms("core", "0.1.0"), Some(5_500));
        // Corrupt reports cannot overflow the arithmetic.
        assert_eq!(saturating_sum([u64::MAX, 1]), u64::MAX);
    }

    #[test]
    fn only_duplicate_compile_prices_are_marked_measured() {
        let inputs = AdviseInputs {
            rebuild_tails: vec![("core".into(), 9_000, 4)],
            link_ms: vec![("app bin \"app\"".into(), 12_000)],
            version_spread: vec![("syn".into(), 2, Some(4_500)), ("rand".into(), 2, None)],
            ..AdviseInputs::default()
        };
        let rows: BTreeMap<_, _> = advise(&inputs)
            .into_iter()
            .map(|advice| row(advice, &BTreeMap::new()))
            .map(|row| (row.subject.clone(), row))
            .collect();
        // A measured tail or link time yields an estimated saving (half).
        assert_eq!(rows["core"].expected_saved_ms, 4_500);
        assert!(!rows["core"].measured);
        assert!(!rows["app bin \"app\""].measured);
        assert!(rows["syn"].measured);
        assert!(!rows["rand"].measured);
    }

    #[test]
    fn discovery_reads_newest_reports_first_and_skips_the_alias() {
        let directory = tempfile::tempdir().unwrap();
        for name in [
            "cargo-timing.html",
            "cargo-timing-20261101T000000Z-aa.html",
            "cargo-timing-20261103T000000Z-bb.html",
            "cargo-timing-20261102T000000Z-cc.html",
            "notes.txt",
        ] {
            std::fs::write(directory.path().join(name), "").unwrap();
        }
        let found = discover_timing_reports(directory.path(), 2);
        let names: Vec<_> = found
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "cargo-timing-20261103T000000Z-bb.html",
                "cargo-timing-20261102T000000Z-cc.html"
            ]
        );
        assert!(discover_timing_reports(&directory.path().join("absent"), 5).is_empty());
    }

    /// The planted-split workload: a real workspace, really built by Cargo
    /// three times with different feature selections, plus a duplicated
    /// dependency. The advice must find both plants from the real reports.
    #[test]
    fn a_real_cargo_workload_with_planted_splits_yields_measured_advice() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        let write = |path: &str, contents: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        };
        write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"common\", \"a\", \"b\", \"c\"]\nexclude = [\"dup1\", \"dup2\"]\nresolver = \"2\"\n",
        );
        write(
            "common/Cargo.toml",
            "[package]\nname = \"common\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\nf1 = []\nf2 = []\nf3 = []\n",
        );
        write("common/src/lib.rs", "pub fn value() -> u32 { 1 }\n");
        for (member, feature, dup) in [
            ("a", "f1", "dup1"),
            ("b", "f2", "dup2"),
            ("c", "f3", "dup1"),
        ] {
            write(
                &format!("{member}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncommon = {{ path = \"../common\", features = [\"{feature}\"] }}\ndup = {{ path = \"../{dup}\" }}\n"
                ),
            );
            write(
                &format!("{member}/src/lib.rs"),
                "pub fn run() -> u32 { common::value() + dup::value() }\n",
            );
        }
        for (directory, version) in [("dup1", "0.1.0"), ("dup2", "0.2.0")] {
            write(
                &format!("{directory}/Cargo.toml"),
                &format!(
                    "[package]\nname = \"dup\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
            );
            write(
                &format!("{directory}/src/lib.rs"),
                "pub fn value() -> u32 { 2 }\n",
            );
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let target = root.join("target");
        for member in ["a", "b", "c"] {
            let status = Command::new(&cargo)
                .args(["build", "--offline", "--timings", "-p", member])
                .env("CARGO_TARGET_DIR", &target)
                .current_dir(root)
                .status()
                .unwrap();
            assert!(status.success(), "cargo build -p {member}");
        }
        let manifest = root.join("Cargo.toml");
        let platform = host_platform();
        let meta = cargo_metadata(&manifest, platform.as_deref()).unwrap();
        let reports = discover_timing_reports(&target.join("cargo-timings"), 20);
        assert_eq!(reports.len(), 3, "one report per build");
        let report = build_report(&meta, platform, &reports);
        assert_eq!(report.timing_reports.len(), 3);
        assert_eq!(report.profile.as_deref(), Some("dev"));

        let features = report
            .advice
            .iter()
            .find(|row| row.kind == "reduce_feature_coupling")
            .expect("the planted feature split");
        assert_eq!(features.subject, "common");
        assert!(features.measured);
        assert!(features.evidence[0].contains("3 distinct feature sets"));

        let versions = report
            .advice
            .iter()
            .find(|row| row.kind == "align_versions")
            .expect("the planted duplicate version");
        assert_eq!(versions.subject, "dup");
        assert!(versions.measured, "{versions:?}");
        assert!(
            versions
                .evidence
                .iter()
                .any(|line| line == "versions: 0.1.0, 0.2.0")
        );
        // Nothing unplanted is advised. The only legitimate extra row is a
        // rebuild tail for `common` on a machine slow enough to cross its
        // threshold, and that saving is an estimate, never "measured".
        for row in &report.advice {
            match (row.kind.as_str(), row.subject.as_str()) {
                ("reduce_feature_coupling", "common") | ("align_versions", "dup") => {}
                ("split_rebuild_tail_crate", "common") => assert!(!row.measured),
                _ => panic!("unplanted advice: {row:#?}"),
            }
        }
        // Nothing was edited.
        assert_eq!(
            std::fs::read_to_string(root.join("common/src/lib.rs")).unwrap(),
            "pub fn value() -> u32 { 1 }\n"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["evidence_limits"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn corpus_and_cas_root_feed_test_dominance_and_fragmentation_diagnostics() {
        use rabs_cas::metadata_store::{
            AuthorityRow, RabsMetadataStore, RusqliteEngine, SqlMetadataStore,
        };
        use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};

        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("invocations.ndjsonl");
        let lines = [
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "tool": "CargoWholeCommand",
                "argv_redacted": ["cargo test -p slow_suite"],
                "cwd_redacted": "/work/app",
                "duration_ms": 8_000_u64,
            })
            .to_string(),
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "tool": "Nextest",
                "argv_redacted": ["cargo nextest run -p fast_suite"],
                "cwd_redacted": "/work/app",
                "duration_ms": 2_000_u64,
            })
            .to_string(),
            serde_json::json!({
                "schema": "rabs.invocation-record",
                "tool": "CargoWholeCommand",
                "argv_redacted": ["cargo check --workspace"],
                "cwd_redacted": "/work/app",
                "duration_ms": 50_000_u64,
            })
            .to_string(),
            "{malformed json".to_owned(),
        ];
        std::fs::write(&corpus, lines.join("\n")).unwrap();

        let cas_root = dir.path().join("cas");
        std::fs::create_dir_all(&cas_root).unwrap();
        let mut store =
            SqlMetadataStore::open(RusqliteEngine::open(&cas_root.join("meta.sqlite")).unwrap())
                .unwrap();
        let authority = AuthorityRow {
            digest: rabs_key::typed_digest::compute("rabs.advise-auth.v1", b"active"),
            cluster_id: "advise-test".to_owned(),
            incarnation: 1,
            term: 1,
            acquired_seq: 1,
        };
        store.acquire_authority(&authority).unwrap();
        let base = rabs_key::typed_digest::compute("rabs.advise-base.v1", b"base");
        for tc in ["nightly-a", "nightly-b"] {
            let desc = ActionDescriptor {
                key_epoch: 1,
                projection_epoch: 1,
                action_class: ActionClass::RustcDependencyCompile,
                normalized_invocation: base.clone(),
                virtual_working_directory: base.clone(),
                action_inputs: base.clone(),
                negative_dependencies: base.clone(),
                dependency_inputs: base.clone(),
                toolchain: rabs_key::typed_digest::compute("rabs.toolchain.v1", tc.as_bytes()),
                output_platform: base.clone(),
                environment: base.clone(),
                sandbox_semantic_policy: base.clone(),
                build_path_semantic_policy: base.clone(),
                execution_semantics: base.clone(),
                output_declarations: base.clone(),
            };
            store
                .record_action_key_provenance(&authority.digest, &desc, "rustc-dependency-compile")
                .unwrap();
        }
        drop(store);

        let meta = metadata(serde_json::json!({
            "packages": [package("app", "app", "0.1.0", "bin")],
            "workspace_members": ["app"],
            "resolve": {"nodes": [{"id": "app", "deps": []}]},
            "target_directory": "/t",
            "workspace_root": "/w",
        }));
        let report = build_report_with_sources(
            &meta,
            Some("x86_64-unknown-linux-gnu".to_owned()),
            &[],
            Some(&cas_root),
            Some(&corpus),
        )
        .unwrap();

        let dom = report
            .advice
            .iter()
            .find(|row| row.kind == "dominating_tests")
            .expect("dominating test suite from corpus");
        assert_eq!(dom.subject, "app::slow_suite");
        assert!(dom.evidence.iter().any(|e| e.contains("800 permille")));
        assert!(
            !report
                .evidence_limits
                .iter()
                .any(|l| l.starts_with("test dominance:"))
        );
        let corpus_summary = report.corpus_tests.as_ref().unwrap();
        assert_eq!(corpus_summary.records_parsed, 3);
        assert_eq!(corpus_summary.test_invocations, 2);
        assert_eq!(corpus_summary.malformed_lines, 1);
        assert_eq!(corpus_summary.total_test_wall_ms, 10_000);

        let cas_frag = report.cas_fragmentation.as_ref().unwrap();
        assert_eq!(cas_frag.verified_actions, 2);
        assert_eq!(cas_frag.fragmenters.len(), 1);
        assert_eq!(cas_frag.fragmenters[0].component, "toolchain");
    }
}
