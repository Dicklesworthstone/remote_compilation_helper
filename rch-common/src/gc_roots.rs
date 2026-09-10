//! The single source of truth for the directory roots `rch gc` scans.
//!
//! # Why this module exists
//!
//! rch creates long-lived, multi-GB runtime state on a worker in exactly three
//! places, and every one of them is derived from a value that already lives
//! somewhere else in this crate:
//!
//! 1. **The project mirror** — `[remediation.pooled_target] remote_base`
//!    (default [`crate::remediation_config::DEFAULT_POOLED_REMOTE_BASE`]).
//!    Pooled target stores land at
//!    `<remote_base>/<project>/.rch-target-<worker>-pool-<key>`.
//! 2. **The relocated pooled store** — `[remediation.pooled_target] store_base`
//!    (issue #64), when an operator moves warm pools onto a bigger volume.
//! 3. **The worker temp base** — resolved *on the worker* by
//!    [`crate::remote_compilation::remote_cargo_home_base_prelude`] as
//!    `$TMPDIR` → `/data/tmp` → `/tmp`. Both the durable per-worker Cargo
//!    caches ([`crate::remote_compilation::RCH_CARGO_CACHE_PREFIX`], issue #42)
//!    and staged `.rch-target-*` dirs live under it.
//!
//! Before this module the GC scan set was a **second, hardcoded list**: the
//! surface config built `[remote_base, store_base]` by hand and the reap script
//! re-implemented the `$TMPDIR` → `/data/tmp` → `/tmp` ladder inline instead of
//! calling the prelude that creates the dirs. Two lists that must agree but are
//! written twice always drift, and this pair drifted badly: workers whose real
//! runtime roots sat elsewhere (an operator build root on a mounted volume, a
//! `$TMPDIR` that differed between dir-creation time and sweep time) were never
//! scanned, so `rch gc` truthfully reported "0 dirs, 0 MB" on every worker while
//! hundreds of GB of `.rch-target-*-pool-*` and `rch-cargo-cache-*` sat on disk
//! (~700 GB fleet-wide before the 2026-09 sweep).
//!
//! [`derive_gc_roots`] is now the only place a root set is constructed. It
//! folds the config-derived roots, any operator-configured extra roots
//! (`[remediation.pooled_target] gc_extra_roots`) and any `--root` flags into
//! one validated, de-duplicated, order-stable list, and it always reports the
//! worker temp base as a first-class root so `rch gc` output names every place
//! it looked.

use crate::remediation_config::PooledTargetConfig;
use crate::stale_target_reap::is_safe_reap_base;

/// Where a scan root came from. Reported per root so an operator reading
/// `rch gc` output can tell a default from something they configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GcRootSource {
    /// `[remediation.pooled_target] remote_base` — the project mirror.
    PooledRemoteBase,
    /// `[remediation.pooled_target] store_base` — a relocated pooled store.
    PooledStoreBase,
    /// `[remediation.pooled_target] gc_extra_roots` — operator-configured.
    ConfiguredExtra,
    /// A `--root` flag on this invocation.
    CommandLine,
    /// The worker temp base, resolved on the worker at sweep time by
    /// [`crate::remote_compilation::remote_cargo_home_base_prelude`].
    WorkerTempBase,
}

impl GcRootSource {
    /// Stable, machine-readable tag used in JSON output and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PooledRemoteBase => "pooled_remote_base",
            Self::PooledStoreBase => "pooled_store_base",
            Self::ConfiguredExtra => "configured_extra",
            Self::CommandLine => "command_line",
            Self::WorkerTempBase => "worker_temp_base",
        }
    }

    /// The config key or flag an operator edits to change this root.
    #[must_use]
    pub const fn origin_hint(self) -> &'static str {
        match self {
            Self::PooledRemoteBase => "[remediation.pooled_target] remote_base",
            Self::PooledStoreBase => "[remediation.pooled_target] store_base",
            Self::ConfiguredExtra => "[remediation.pooled_target] gc_extra_roots",
            Self::CommandLine => "--root",
            Self::WorkerTempBase => "$TMPDIR → /data/tmp → /tmp (resolved on the worker)",
        }
    }
}

impl std::fmt::Display for GcRootSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Placeholder path reported for [`GcRootSource::WorkerTempBase`]. The real
/// path is only knowable on the worker, so the sweep script resolves it there
/// and echoes the resolved value back (see
/// `stale_target_reap::parse_scan_roots`); this constant is what the client
/// prints before it has that answer.
pub const WORKER_TEMP_BASE_PLACEHOLDER: &str = "<worker temp base>";

/// One root `rch gc` scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcRoot {
    /// Absolute path on the worker, `/`-trimmed. For
    /// [`GcRootSource::WorkerTempBase`] this is
    /// [`WORKER_TEMP_BASE_PLACEHOLDER`].
    pub path: String,
    /// Where this root came from.
    pub source: GcRootSource,
}

impl GcRoot {
    /// Whether this root is resolved on the worker rather than by the client,
    /// i.e. it carries no usable client-side path.
    #[must_use]
    pub fn is_worker_resolved(&self) -> bool {
        self.source == GcRootSource::WorkerTempBase
    }
}

/// A root that failed validation. Rejected roots are never scanned — the path
/// is embedded into a generated remote shell command, so anything that could
/// escape its double-quoted context, traverse upward, or name the filesystem
/// root is refused outright rather than sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcRootRejection {
    /// The offending value, verbatim.
    pub path: String,
    /// Where it came from.
    pub source: GcRootSource,
    /// Human-readable reason.
    pub reason: String,
}

impl std::fmt::Display for GcRootRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} root {:?} ({}) is unusable: {}",
            self.source,
            self.path,
            self.source.origin_hint(),
            self.reason
        )
    }
}

/// The validated, de-duplicated root set for one `rch gc` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcRootSet {
    /// Roots to scan, in a stable order: pooled remote base, pooled store
    /// base, configured extras, `--root` flags, then the worker temp base.
    pub roots: Vec<GcRoot>,
    /// Roots that failed validation and will NOT be scanned.
    pub rejected: Vec<GcRootRejection>,
}

impl GcRootSet {
    /// The client-resolvable roots, i.e. every root except the worker temp
    /// base. These are the paths handed to the remote enumeration/sweep
    /// scripts as `$base`.
    #[must_use]
    pub fn scan_bases(&self) -> Vec<String> {
        self.roots
            .iter()
            .filter(|r| !r.is_worker_resolved())
            .map(|r| r.path.clone())
            .collect()
    }

    /// Look up which configured root a discovered absolute path belongs to.
    ///
    /// Attribution is longest-prefix so a `store_base` nested inside
    /// `remote_base` still wins, and it is path-segment aware so
    /// `/data/projects-old/x` is never attributed to `/data/projects`.
    /// Returns `None` for a path under no configured root — in practice a dir
    /// found under the worker-resolved temp base.
    #[must_use]
    pub fn attribute<'a>(&'a self, path: &str) -> Option<&'a GcRoot> {
        self.roots
            .iter()
            .filter(|root| !root.is_worker_resolved())
            .filter(|root| path_is_under(path, &root.path))
            .max_by_key(|root| root.path.len())
    }
}

/// Whether `path` is `base` itself or lives beneath it, comparing whole path
/// segments (so `/data/projects-old` is not under `/data/projects`).
#[must_use]
pub fn path_is_under(path: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        return false;
    }
    if path == base {
        return true;
    }
    path.strip_prefix(base)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn normalize(path: &str) -> String {
    let trimmed = path.trim();
    let stripped = trimmed.trim_end_matches('/');
    if stripped.is_empty() {
        trimmed.to_string()
    } else {
        stripped.to_string()
    }
}

/// Build the root set for a `rch gc` run.
///
/// `pooled` supplies the config-derived roots; `cli_roots` are `--root` flags
/// (already in the order the operator gave them). Every candidate is validated
/// with [`is_safe_reap_base`]; failures land in [`GcRootSet::rejected`] rather
/// than aborting, so one bad `--root` cannot stop the sweep of the good ones —
/// but a rejected root is never scanned, and callers surface the rejection.
///
/// The worker temp base is always appended: it is where
/// [`crate::remote_compilation::remote_cargo_cache_expr`] puts durable Cargo
/// caches and where staged `.rch-target-*` dirs live, and it is resolved on the
/// worker by the very prelude that creates them.
#[must_use]
pub fn derive_gc_roots(pooled: &PooledTargetConfig, cli_roots: &[String]) -> GcRootSet {
    let mut roots: Vec<GcRoot> = Vec::new();
    let mut rejected: Vec<GcRootRejection> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut push = |raw: &str, source: GcRootSource| {
        let path = normalize(raw);
        if path.is_empty() {
            rejected.push(GcRootRejection {
                path: raw.to_string(),
                source,
                reason: "empty path".to_string(),
            });
            return;
        }
        if !is_safe_reap_base(&path) {
            rejected.push(GcRootRejection {
                path: raw.to_string(),
                source,
                reason: "not an absolute, `..`-free path of at least one segment built from \
                         [A-Za-z0-9/._-] (it is embedded in a remote shell command)"
                    .to_string(),
            });
            return;
        }
        if seen.insert(path.clone()) {
            roots.push(GcRoot { path, source });
        }
    };

    push(&pooled.remote_base, GcRootSource::PooledRemoteBase);
    if let Some(store_base) = pooled.store_base.as_deref() {
        push(store_base, GcRootSource::PooledStoreBase);
    }
    for extra in &pooled.gc_extra_roots {
        push(extra, GcRootSource::ConfiguredExtra);
    }
    for cli in cli_roots {
        push(cli, GcRootSource::CommandLine);
    }
    drop(push);

    roots.push(GcRoot {
        path: WORKER_TEMP_BASE_PLACEHOLDER.to_string(),
        source: GcRootSource::WorkerTempBase,
    });

    GcRootSet { roots, rejected }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PooledTargetConfig {
        PooledTargetConfig::default()
    }

    #[test]
    fn default_root_set_is_remote_base_plus_worker_temp_base() {
        let set = derive_gc_roots(&cfg(), &[]);
        assert_eq!(
            set.roots,
            vec![
                GcRoot {
                    path: "/data/projects".to_string(),
                    source: GcRootSource::PooledRemoteBase,
                },
                GcRoot {
                    path: WORKER_TEMP_BASE_PLACEHOLDER.to_string(),
                    source: GcRootSource::WorkerTempBase,
                },
            ]
        );
        assert!(set.rejected.is_empty());
        assert_eq!(set.scan_bases(), vec!["/data/projects".to_string()]);
    }

    /// The gap this module closes: a pool root rch itself writes to must be
    /// scannable from configuration alone, with no code change.
    #[test]
    fn configured_extra_roots_and_cli_roots_are_scanned() {
        let mut c = cfg();
        c.store_base = Some("/bigdisk/rch-pools".to_string());
        c.gc_extra_roots = vec!["/Volumes/EE1/rch".to_string(), "/srv/rch".to_string()];
        let set = derive_gc_roots(&c, &["/private/tmp/ee-reality-1".to_string()]);

        assert_eq!(
            set.scan_bases(),
            vec![
                "/data/projects".to_string(),
                "/bigdisk/rch-pools".to_string(),
                "/Volumes/EE1/rch".to_string(),
                "/srv/rch".to_string(),
                "/private/tmp/ee-reality-1".to_string(),
            ]
        );
        assert!(set.rejected.is_empty(), "{:?}", set.rejected);
        assert_eq!(
            set.roots.last().map(|r| r.source),
            Some(GcRootSource::WorkerTempBase),
            "the worker temp base is always scanned last"
        );
    }

    #[test]
    fn duplicate_roots_collapse_and_keep_first_source() {
        let mut c = cfg();
        c.store_base = Some("/data/projects/".to_string());
        c.gc_extra_roots = vec!["/data/projects".to_string()];
        let set = derive_gc_roots(&c, &["/data/projects//".to_string()]);
        assert_eq!(set.scan_bases(), vec!["/data/projects".to_string()]);
        assert_eq!(set.roots[0].source, GcRootSource::PooledRemoteBase);
    }

    #[test]
    fn unsafe_roots_are_rejected_not_sanitized() {
        let c = cfg();
        let bad = [
            "/",
            "relative/path",
            "/tmp/../etc",
            "/tmp/$(whoami)",
            "/tmp/rch; rm -rf x",
            "",
            "   ",
        ];
        for candidate in bad {
            let set = derive_gc_roots(&c, &[candidate.to_string()]);
            assert_eq!(
                set.scan_bases(),
                vec!["/data/projects".to_string()],
                "{candidate:?} must never become a scan base"
            );
            assert!(
                set.rejected
                    .iter()
                    .any(|r| r.source == GcRootSource::CommandLine && r.path == candidate),
                "{candidate:?} must be reported as rejected"
            );
        }
    }

    /// One bad `--root` must not disable the sweep of the good roots.
    #[test]
    fn a_rejected_root_does_not_drop_the_valid_ones() {
        let set = derive_gc_roots(&cfg(), &["/".to_string(), "/srv/rch".to_string()]);
        assert_eq!(
            set.scan_bases(),
            vec!["/data/projects".to_string(), "/srv/rch".to_string()]
        );
        assert_eq!(set.rejected.len(), 1);
        assert!(set.rejected[0].to_string().contains("unusable"));
    }

    #[test]
    fn attribution_is_longest_prefix_and_segment_aware() {
        let mut c = cfg();
        c.gc_extra_roots = vec![
            "/data/projects/nested".to_string(),
            "/data/projects-old".to_string(),
        ];
        let set = derive_gc_roots(&c, &[]);

        assert_eq!(
            set.attribute("/data/projects/nested/x/.rch-target-w-pool-a")
                .map(|r| r.path.as_str()),
            Some("/data/projects/nested"),
        );
        assert_eq!(
            set.attribute("/data/projects/x/.rch-target-w-pool-a")
                .map(|r| r.path.as_str()),
            Some("/data/projects"),
        );
        assert_eq!(
            set.attribute("/data/projects-old/x")
                .map(|r| r.path.as_str()),
            Some("/data/projects-old"),
            "a sibling root must not be swallowed by a prefix match",
        );
        assert_eq!(set.attribute("/data/tmp/rch-cargo-cache-hz2"), None);
    }

    #[test]
    fn path_is_under_compares_whole_segments() {
        assert!(path_is_under("/a/b", "/a/b"));
        assert!(path_is_under("/a/b/c", "/a/b"));
        assert!(path_is_under("/a/b/c", "/a/b/"));
        assert!(!path_is_under("/a/bc", "/a/b"));
        assert!(!path_is_under("/a", "/a/b"));
        assert!(!path_is_under("/a/b", ""));
        assert!(!path_is_under("/a/b", "/"));
    }
}
