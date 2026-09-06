//! rsync flavour detection, binary resolution, and argv compatibility
//! (issue #66).
//!
//! rch drives rsync with 3.x-only flags (`--info=progress2`, `--info=stats2`,
//! `--info=name2`, `--compress-choice=zstd`, `--append-verify`). Not every
//! `rsync` on PATH accepts them: a stock macOS `/usr/bin/rsync` is
//! **openrsync** (protocol 29, "rsync 2.6.9 compatible"), older macOS shipped
//! Apple's real rsync 2.6.9, and OpenBSD ships openrsync in base. Those
//! binaries reject the flags with `unrecognized option` and exit 1 before a
//! single byte moves.
//!
//! This module does three things:
//!
//! 1. [`RsyncFlavor::parse_version_output`] classifies `rsync --version`
//!    output and [`RsyncCapabilities`] maps the flavour to the concrete argv
//!    fragments every transfer builder needs (progress, stats, per-file
//!    listing, compression, resume).
//! 2. [`resolve_rsync`] picks the binary: an explicit override
//!    (`RCH_RSYNC_BIN`, then `[transfer] rsync_bin`) wins; otherwise the PATH
//!    binary is used when it is a modern rsync, and a modern rsync in the
//!    well-known Homebrew/MacPorts/pkg locations is preferred over a legacy
//!    PATH binary. Only when nothing modern exists does rch fall back to the
//!    legacy binary with the compatibility argv.
//! 3. [`resolve_rsync_cached`] memoizes the resolution per process. A
//!    `--version` probe costs ~3 ms and the hook is a short-lived process, so
//!    an on-disk cache would add a staleness surface for no measurable gain.
//!
//! The compatibility argv was verified against openrsync on macOS: it accepts
//! `--progress`, `--stats`, `-vv`, `--out-format=%i %n`, `--itemize-changes`,
//! `--partial-dir`, `--no-motd`, `--safe-links`, `--prune-empty-dirs`,
//! `--bwlimit`, `--compress-level`, `--rsync-path`, filter rules, and `-e`.
//! It rejects every `--info=*` value, `--compress-choice`, `--append-verify`,
//! `--msgs2stderr`, `--outbuf`, `--mkpath`, and `--chown`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Environment variable naming an explicit rsync binary. Takes precedence
/// over `[transfer] rsync_bin` so a single shell can be pointed at a test
/// build without editing config.
pub const RSYNC_BIN_ENV: &str = "RCH_RSYNC_BIN";

/// Well-known locations of a package-manager rsync that may not be on the
/// PATH the hook inherits (Homebrew on Apple Silicon and Intel, MacPorts,
/// BSD pkg / older Homebrew, Homebrew's keg path).
pub const PREFERRED_RSYNC_LOCATIONS: &[&str] = &[
    "/opt/homebrew/bin/rsync",
    "/usr/local/bin/rsync",
    "/opt/local/bin/rsync",
    "/usr/local/opt/rsync/bin/rsync",
    "/opt/homebrew/opt/rsync/bin/rsync",
];

/// Oldest upstream rsync rch will drive at all. Apple shipped 2.6.9 for
/// years and openrsync declares compatibility with it; anything older lacks
/// `--out-format`, which the artifact manifest depends on.
pub const MIN_SUPPORTED_RSYNC: (u32, u32, u32) = (2, 6, 9);

/// Hard cap on the `--version` probe so a wedged binary or a stalled network
/// filesystem never hangs the hook.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest `--compress-level` zlib accepts; a legacy rsync compresses with
/// zlib because `--compress-choice=zstd` is unavailable.
const MAX_ZLIB_COMPRESS_LEVEL: u32 = 9;

/// Which rsync implementation a binary is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RsyncFlavor {
    /// Upstream (samba.org) rsync, any version.
    Rsync { major: u32, minor: u32, patch: u32 },
    /// openrsync (OpenBSD's BSD-licensed reimplementation; stock macOS 15+).
    OpenRsync {
        /// Wire protocol version openrsync announces (`29` on macOS).
        protocol: Option<u32>,
    },
    /// `--version` output rch could not classify.
    Unknown,
}

impl RsyncFlavor {
    /// Classify the output of `rsync --version`.
    ///
    /// Recognized shapes (first non-empty line):
    ///
    /// ```text
    /// rsync  version 3.4.1  protocol version 32        (upstream 3.x)
    /// rsync  version 2.6.9  protocol version 29        (Apple's legacy build)
    /// openrsync: protocol version 29                   (openrsync)
    /// ```
    ///
    /// openrsync is checked first because its second line reads
    /// `rsync version 2.6.9 compatible`, which a naive version-line scan would
    /// misclassify as upstream 2.6.9.
    #[must_use]
    pub fn parse_version_output(text: &str) -> Self {
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let Some(first) = lines.next() else {
            return Self::Unknown;
        };
        let lowered = first.to_ascii_lowercase();
        if lowered.starts_with("openrsync") {
            let protocol = lowered
                .split("protocol version")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|token| token.parse().ok());
            return Self::OpenRsync { protocol };
        }
        if lowered.starts_with("rsync")
            && let Some(rest) = lowered.split("version").nth(1)
            && let Some(token) = rest.split_whitespace().next()
            && let Some((major, minor, patch)) = parse_semver_prefix(token)
        {
            return Self::Rsync {
                major,
                minor,
                patch,
            };
        }
        Self::Unknown
    }

    /// Whether this flavour understands rsync 3.1+'s `--info=` family, i.e.
    /// rch's preferred argv works unmodified.
    #[must_use]
    pub const fn supports_info_flags(self) -> bool {
        self.capabilities().info_flags
    }

    /// Whether rch can drive this binary at all (natively or through the
    /// compatibility argv). `Unknown` is assumed drivable: refusing would turn
    /// an unrecognized `--version` banner into a hard outage, and the doctor
    /// surfaces the uncertainty separately.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        match self {
            Self::Rsync {
                major,
                minor,
                patch,
            } => {
                let (min_major, min_minor, min_patch) = MIN_SUPPORTED_RSYNC;
                if major != min_major {
                    major > min_major
                } else if minor != min_minor {
                    minor > min_minor
                } else {
                    patch >= min_patch
                }
            }
            Self::OpenRsync { .. } | Self::Unknown => true,
        }
    }

    /// Argv capabilities of this flavour.
    ///
    /// `Unknown` maps to the modern set: that is exactly what rch did before
    /// flavour detection existed, so an unclassifiable banner never changes
    /// behaviour for a working setup.
    #[must_use]
    pub const fn capabilities(self) -> RsyncCapabilities {
        match self {
            Self::Rsync { major, minor, .. } => RsyncCapabilities {
                // --info= arrived in 3.1.0 (with the stats2 / name2 / progress2
                // values and the `(reg: N, dir: M)` stats breakdown).
                info_flags: version_at_least(major, minor, 3, 1),
                stats_regular_file_breakdown: version_at_least(major, minor, 3, 1),
                // --compress-choice / zstd arrived in 3.2.0.
                compress_choice: version_at_least(major, minor, 3, 2),
                // --append-verify and --no-motd arrived in 3.0.0.
                append_verify: version_at_least(major, minor, 3, 0),
                no_motd: version_at_least(major, minor, 3, 0),
            },
            Self::OpenRsync { .. } => RsyncCapabilities {
                info_flags: false,
                stats_regular_file_breakdown: false,
                compress_choice: false,
                append_verify: false,
                no_motd: true,
            },
            Self::Unknown => RsyncCapabilities::MODERN,
        }
    }
}

impl fmt::Display for RsyncFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsync {
                major,
                minor,
                patch,
            } => write!(f, "rsync {major}.{minor}.{patch}"),
            Self::OpenRsync {
                protocol: Some(protocol),
            } => write!(f, "openrsync (protocol {protocol})"),
            Self::OpenRsync { protocol: None } => f.write_str("openrsync"),
            Self::Unknown => f.write_str("unrecognized rsync"),
        }
    }
}

const fn version_at_least(major: u32, minor: u32, want_major: u32, want_minor: u32) -> bool {
    major > want_major || (major == want_major && minor >= want_minor)
}

fn parse_semver_prefix(token: &str) -> Option<(u32, u32, u32)> {
    // Accept `3.4.1`, `3.4.1-dev`, `3.2.7pre1`, `2.6.9`: digits and dots up to
    // the first character that is neither.
    let numeric: String = token
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    let mut parts = numeric.split('.').filter(|part| !part.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |part| part.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |part| part.parse().ok())?;
    Some((major, minor, patch))
}

/// What a given rsync binary accepts. Every transfer builder asks this
/// struct for its argv fragments instead of hard-coding rsync 3.x flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RsyncCapabilities {
    /// `--info=progress2` / `--info=stats2` / `--info=name2` (rsync >= 3.1).
    pub info_flags: bool,
    /// `--stats` prints `Number of files: N (reg: R, dir: D)` (rsync >= 3.1),
    /// which the zero-build-output detector uses as its completeness
    /// cross-check. Without it the detector fails open.
    pub stats_regular_file_breakdown: bool,
    /// `--compress-choice=zstd` (rsync >= 3.2). Without it `-z` means zlib and
    /// `--compress-level` is capped at 9.
    pub compress_choice: bool,
    /// `--append-verify` (rsync >= 3.0). Without it resumable uploads rely on
    /// `--partial` plus the delta algorithm alone.
    pub append_verify: bool,
    /// `--no-motd` (rsync >= 3.0, openrsync).
    pub no_motd: bool,
}

impl RsyncCapabilities {
    /// Everything rch's preferred argv needs (rsync >= 3.2).
    pub const MODERN: Self = Self {
        info_flags: true,
        stats_regular_file_breakdown: true,
        compress_choice: true,
        append_verify: true,
        no_motd: true,
    };

    /// The openrsync / rsync 2.6.9 compatibility set.
    pub const LEGACY: Self = Self {
        info_flags: false,
        stats_regular_file_breakdown: false,
        compress_choice: false,
        append_verify: false,
        no_motd: false,
    };

    /// Whether the compatibility argv (rather than the preferred one) is in
    /// use.
    #[must_use]
    pub const fn is_compatibility_mode(&self) -> bool {
        !self.info_flags
    }

    /// Progress reporting that refreshes often enough to feed the silence
    /// stall detector. `--info=progress2` prints one cumulative line refreshed
    /// with bare `\r`; legacy `--progress` prints a per-file line in the same
    /// `<bytes> <pct>% <rate> <eta> (xfer#N, to-check=A/B)` shape.
    #[must_use]
    pub const fn progress_args(&self) -> &'static [&'static str] {
        if self.info_flags {
            &["--info=progress2"]
        } else {
            &["--progress"]
        }
    }

    /// Transfer statistics block (`Number of files transferred:`, `sent N
    /// bytes`). Both spellings print the lines `parse_rsync_bytes` /
    /// `parse_rsync_files` read.
    #[must_use]
    pub const fn stats_args(&self) -> &'static [&'static str] {
        if self.info_flags {
            &["--info=stats2"]
        } else {
            &["--stats"]
        }
    }

    /// Make rsync itemize EVERY matched regular file, including up-to-date
    /// ones (`.f` lines), when combined with `--out-format='%i %n'`.
    /// `--info=name2` is the modern spelling; `-vv` is the pre-3.1 one and is
    /// what openrsync honours (verified: `-v` alone lists only transferred
    /// files, `-vv` also lists the `.f` matches).
    #[must_use]
    pub const fn name_listing_args(&self) -> &'static [&'static str] {
        if self.info_flags {
            &["--info=name2"]
        } else {
            &["-vv"]
        }
    }

    /// Compression flags for a requested zstd level (`0` disables).
    ///
    /// Modern rsync gets `--compress-choice=zstd --compress-level=N`. A legacy
    /// binary compresses with zlib via the `-z` every builder already passes,
    /// so only `--compress-level` is emitted, clamped to zlib's maximum of 9.
    #[must_use]
    pub fn compression_args(&self, level: u32) -> Vec<String> {
        if level == 0 {
            return Vec::new();
        }
        if self.compress_choice {
            vec![
                "--compress-choice=zstd".to_string(),
                format!("--compress-level={level}"),
            ]
        } else {
            vec![format!(
                "--compress-level={}",
                level.min(MAX_ZLIB_COMPRESS_LEVEL)
            )]
        }
    }

    /// Resumable-upload flags for an immutable file: `--partial` always,
    /// plus `--append-verify` where supported so a retry extends the remote
    /// partial in place instead of re-deltaing it.
    #[must_use]
    pub const fn resume_args(&self) -> &'static [&'static str] {
        if self.append_verify {
            &["--partial", "--append-verify"]
        } else {
            &["--partial"]
        }
    }

    /// `--no-motd` where supported (suppresses daemon-mode banners that would
    /// pollute parsed stdout); nothing otherwise.
    #[must_use]
    pub const fn no_motd_args(&self) -> &'static [&'static str] {
        if self.no_motd { &["--no-motd"] } else { &[] }
    }
}

/// How the resolved binary was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsyncSource {
    /// `RCH_RSYNC_BIN` in the environment.
    Env,
    /// `[transfer] rsync_bin` in config.
    Config,
    /// First `rsync` on PATH.
    Path,
    /// A modern rsync in [`PREFERRED_RSYNC_LOCATIONS`], chosen over a legacy
    /// PATH binary.
    PreferredLocation,
}

impl fmt::Display for RsyncSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Env => RSYNC_BIN_ENV,
            Self::Config => "[transfer] rsync_bin",
            Self::Path => "PATH",
            Self::PreferredLocation => "well-known install location",
        })
    }
}

/// The rsync binary rch will exec, with its probed flavour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRsync {
    /// Absolute path handed to `Command::new`.
    pub path: PathBuf,
    /// Probed flavour.
    pub flavor: RsyncFlavor,
    /// First line of `--version` output, for diagnostics.
    pub version_line: String,
    /// How the binary was chosen.
    pub source: RsyncSource,
    /// A legacy PATH binary that was skipped in favour of `path`, if any —
    /// surfaced by the doctor so the operator understands why `which rsync`
    /// and rch disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadowed: Option<ShadowedRsync>,
}

/// The PATH rsync that lost to a preferred-location binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowedRsync {
    pub path: PathBuf,
    pub flavor: RsyncFlavor,
}

impl ResolvedRsync {
    /// Argv capabilities of the resolved binary.
    #[must_use]
    pub const fn capabilities(&self) -> RsyncCapabilities {
        self.flavor.capabilities()
    }

    /// One-line human summary, e.g.
    /// `rsync 3.4.1 at /opt/homebrew/bin/rsync (well-known install location; PATH rsync is openrsync (protocol 29) at /usr/bin/rsync)`.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut text = format!(
            "{} at {} ({})",
            self.flavor,
            self.path.display(),
            self.source
        );
        if let Some(shadowed) = &self.shadowed {
            text.push_str(&format!(
                "; PATH rsync is {} at {}",
                shadowed.flavor,
                shadowed.path.display()
            ));
        }
        text
    }
}

/// Why no usable rsync could be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RsyncResolveError {
    /// Nothing named `rsync` on PATH or in the well-known locations.
    #[error("rsync not found on PATH or in {}", PREFERRED_RSYNC_LOCATIONS.join(", "))]
    NotFound,
    /// An explicit override names a binary that does not exist or is not
    /// executable.
    #[error("{origin} points at {path}, which is not an executable file")]
    OverrideMissing { origin: RsyncSource, path: PathBuf },
    /// The binary exists but `--version` failed, hung, or printed nothing.
    #[error("{path} --version failed: {reason}")]
    ProbeFailed { path: PathBuf, reason: String },
}

/// Probe `<path> --version` with a hard timeout and return the first
/// non-empty output line (stdout preferred, stderr as fallback).
pub fn probe_rsync_version(path: &Path) -> Result<String, RsyncResolveError> {
    let fail = |reason: String| RsyncResolveError::ProbeFailed {
        path: path.to_path_buf(),
        reason,
    };
    let mut child = Command::new(path)
        .arg("--version")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| fail(error.to_string()))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() >= VERSION_PROBE_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(format!(
                    "timed out after {}s",
                    VERSION_PROBE_TIMEOUT.as_secs()
                )));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(fail(error.to_string())),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| fail(error.to_string()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = if stdout.trim().is_empty() {
        stderr.as_ref()
    } else {
        stdout.as_ref()
    };
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .ok_or_else(|| fail("no version output".to_string()))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Locate `name` on PATH (first executable hit), mirroring `which`.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_string()]
    } else {
        vec![name.to_string()]
    };
    std::env::split_paths(&path_var)
        .filter(|dir| !dir.as_os_str().is_empty())
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|candidate| is_executable_file(candidate))
}

/// Turn an override value into a concrete path: tilde-expand it, and look a
/// bare name (no separator) up on PATH.
fn override_path(value: &str) -> Option<PathBuf> {
    let expanded = shellexpand::tilde(value.trim()).into_owned();
    if expanded.is_empty() {
        return None;
    }
    let path = PathBuf::from(&expanded);
    if path.components().count() > 1 || path.is_absolute() {
        Some(path)
    } else {
        find_in_path(&expanded).or(Some(path))
    }
}

/// Resolve the rsync binary rch should exec.
///
/// `configured` is `[transfer] rsync_bin`. Precedence: `RCH_RSYNC_BIN`, then
/// `configured`, then PATH (kept when modern), then the first modern binary in
/// [`PREFERRED_RSYNC_LOCATIONS`], then the legacy PATH binary. An explicit
/// override is honoured whatever its flavour — the operator asked for it —
/// but must exist and answer `--version`.
pub fn resolve_rsync(configured: Option<&str>) -> Result<ResolvedRsync, RsyncResolveError> {
    let env_override = std::env::var(RSYNC_BIN_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let explicit = env_override
        .as_deref()
        .map(|value| (value, RsyncSource::Env))
        .or_else(|| {
            configured
                .filter(|value| !value.trim().is_empty())
                .map(|value| (value, RsyncSource::Config))
        });

    if let Some((value, source)) = explicit {
        let path = override_path(value).ok_or_else(|| RsyncResolveError::OverrideMissing {
            origin: source,
            path: PathBuf::from(value),
        })?;
        if !is_executable_file(&path) {
            return Err(RsyncResolveError::OverrideMissing {
                origin: source,
                path,
            });
        }
        let version_line = probe_rsync_version(&path)?;
        return Ok(ResolvedRsync {
            flavor: RsyncFlavor::parse_version_output(&version_line),
            path,
            version_line,
            source,
            shadowed: None,
        });
    }

    let path_candidate = find_in_path("rsync").map(|path| {
        let probed = probe_rsync_version(&path);
        (path, probed)
    });

    // A modern PATH binary is the common case and needs no further probing.
    if let Some((path, Ok(version_line))) = &path_candidate {
        let flavor = RsyncFlavor::parse_version_output(version_line);
        if flavor.supports_info_flags() {
            return Ok(ResolvedRsync {
                path: path.clone(),
                flavor,
                version_line: version_line.clone(),
                source: RsyncSource::Path,
                shadowed: None,
            });
        }
    }

    // Legacy or absent PATH binary: prefer a modern one from a well-known
    // package-manager location.
    for location in PREFERRED_RSYNC_LOCATIONS {
        let path = PathBuf::from(location);
        if path_candidate
            .as_ref()
            .is_some_and(|(path_path, _)| same_file(path_path, &path))
            || !is_executable_file(&path)
        {
            continue;
        }
        let Ok(version_line) = probe_rsync_version(&path) else {
            continue;
        };
        let flavor = RsyncFlavor::parse_version_output(&version_line);
        if !flavor.supports_info_flags() {
            continue;
        }
        let shadowed = path_candidate
            .as_ref()
            .map(|(path_path, probed)| ShadowedRsync {
                path: path_path.clone(),
                flavor: probed
                    .as_deref()
                    .map_or(RsyncFlavor::Unknown, RsyncFlavor::parse_version_output),
            });
        return Ok(ResolvedRsync {
            path,
            flavor,
            version_line,
            source: RsyncSource::PreferredLocation,
            shadowed,
        });
    }

    // Nothing modern anywhere: drive the PATH binary with the compatibility
    // argv, or report that there is no rsync at all.
    match path_candidate {
        Some((path, Ok(version_line))) => Ok(ResolvedRsync {
            flavor: RsyncFlavor::parse_version_output(&version_line),
            path,
            version_line,
            source: RsyncSource::Path,
            shadowed: None,
        }),
        Some((_, Err(error))) => Err(error),
        None => Err(RsyncResolveError::NotFound),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

type ResolveCache = Mutex<HashMap<Option<String>, Result<ResolvedRsync, RsyncResolveError>>>;

fn resolve_cache() -> &'static ResolveCache {
    static CACHE: OnceLock<ResolveCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// [`resolve_rsync`] memoized per process, keyed by the configured override.
///
/// Errors are cached too: a missing binary does not appear between two
/// transfers of the same job, and re-probing on every builder call would
/// only repeat the same failed spawn.
pub fn resolve_rsync_cached(configured: Option<&str>) -> Result<ResolvedRsync, RsyncResolveError> {
    let key = configured.map(str::to_string);
    if let Ok(cache) = resolve_cache().lock()
        && let Some(cached) = cache.get(&key)
    {
        return cached.clone();
    }
    let resolved = resolve_rsync(configured);
    if let Ok(mut cache) = resolve_cache().lock() {
        cache.insert(key, resolved.clone());
    }
    resolved
}

/// Drop the per-process resolution cache (tests, or after `rch config`
/// rewrites `rsync_bin` inside a long-lived process).
pub fn clear_resolve_cache() {
    if let Ok(mut cache) = resolve_cache().lock() {
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from Homebrew rsync 3.4.1 on macOS.
    const RSYNC_3_4_1: &str = "rsync  version 3.4.1  protocol version 32\n\
Copyright (C) 1996-2025 by Andrew Tridgell, Wayne Davison, and others.\n\
Web site: https://rsync.samba.org/\n\
Capabilities:\n    64-bit files, 64-bit inums, 64-bit timestamps, 64-bit long ints,\n";

    /// Captured from Debian bookworm's rsync 3.2.7.
    const RSYNC_3_2_7: &str = "rsync  version 3.2.7  protocol version 31\n\
Copyright (C) 1996-2022 by Andrew Tridgell, Wayne Davison, and others.\n";

    /// Captured from stock macOS `/usr/bin/rsync` (Sequoia and later).
    const OPENRSYNC_MACOS: &str =
        "openrsync: protocol version 29\nrsync version 2.6.9 compatible\n";

    /// Apple's legacy rsync build (macOS up to Sonoma).
    const RSYNC_2_6_9_APPLE: &str = "rsync  version 2.6.9  protocol version 29\n\
Copyright (C) 1996-2006 by Andrew Tridgell, Wayne Davison, and others.\n";

    #[test]
    fn parses_upstream_3x_versions() {
        assert_eq!(
            RsyncFlavor::parse_version_output(RSYNC_3_4_1),
            RsyncFlavor::Rsync {
                major: 3,
                minor: 4,
                patch: 1
            }
        );
        assert_eq!(
            RsyncFlavor::parse_version_output(RSYNC_3_2_7),
            RsyncFlavor::Rsync {
                major: 3,
                minor: 2,
                patch: 7
            }
        );
        assert_eq!(
            RsyncFlavor::parse_version_output("rsync  version 3.2.7pre1  protocol version 31"),
            RsyncFlavor::Rsync {
                major: 3,
                minor: 2,
                patch: 7
            }
        );
        assert_eq!(
            RsyncFlavor::parse_version_output("rsync  version 3.5.0dev  protocol version 32"),
            RsyncFlavor::Rsync {
                major: 3,
                minor: 5,
                patch: 0
            }
        );
    }

    #[test]
    fn parses_openrsync_and_does_not_mistake_its_compat_line_for_2_6_9() {
        assert_eq!(
            RsyncFlavor::parse_version_output(OPENRSYNC_MACOS),
            RsyncFlavor::OpenRsync { protocol: Some(29) }
        );
        assert_eq!(
            RsyncFlavor::parse_version_output("openrsync: protocol version"),
            RsyncFlavor::OpenRsync { protocol: None }
        );
    }

    #[test]
    fn parses_apple_legacy_2_6_9() {
        assert_eq!(
            RsyncFlavor::parse_version_output(RSYNC_2_6_9_APPLE),
            RsyncFlavor::Rsync {
                major: 2,
                minor: 6,
                patch: 9
            }
        );
    }

    #[test]
    fn unrecognized_banner_is_unknown_and_assumed_modern() {
        for text in [
            "",
            "\n\n",
            "rsync: command not found",
            "usage: rsync [-0468BC...]",
        ] {
            assert_eq!(
                RsyncFlavor::parse_version_output(text),
                RsyncFlavor::Unknown,
                "{text:?}"
            );
        }
        assert_eq!(
            RsyncFlavor::Unknown.capabilities(),
            RsyncCapabilities::MODERN
        );
        assert!(RsyncFlavor::Unknown.is_supported());
    }

    #[test]
    fn capabilities_follow_version_thresholds() {
        let v = |major, minor| RsyncFlavor::Rsync {
            major,
            minor,
            patch: 0,
        };
        assert_eq!(v(3, 4).capabilities(), RsyncCapabilities::MODERN);
        assert_eq!(v(3, 2).capabilities(), RsyncCapabilities::MODERN);
        let three_one = v(3, 1).capabilities();
        assert!(three_one.info_flags);
        assert!(three_one.stats_regular_file_breakdown);
        assert!(!three_one.compress_choice);
        assert!(three_one.append_verify);
        let three_zero = v(3, 0).capabilities();
        assert!(!three_zero.info_flags);
        assert!(!three_zero.compress_choice);
        assert!(three_zero.append_verify);
        assert!(three_zero.no_motd);
        assert_eq!(v(2, 6).capabilities(), RsyncCapabilities::LEGACY);
        let openrsync = RsyncFlavor::OpenRsync { protocol: Some(29) }.capabilities();
        assert!(!openrsync.info_flags);
        assert!(!openrsync.compress_choice);
        assert!(!openrsync.append_verify);
        assert!(openrsync.no_motd);
        assert!(openrsync.is_compatibility_mode());
        assert!(!RsyncCapabilities::MODERN.is_compatibility_mode());
    }

    #[test]
    fn support_floor_is_2_6_9() {
        let v = |major, minor, patch| RsyncFlavor::Rsync {
            major,
            minor,
            patch,
        };
        assert!(v(2, 6, 9).is_supported());
        assert!(v(3, 0, 0).is_supported());
        assert!(!v(2, 6, 8).is_supported());
        assert!(!v(2, 5, 7).is_supported());
        assert!(RsyncFlavor::OpenRsync { protocol: None }.is_supported());
    }

    #[test]
    fn argv_fragments_per_flavour() {
        let modern = RsyncCapabilities::MODERN;
        assert_eq!(modern.progress_args(), ["--info=progress2"]);
        assert_eq!(modern.stats_args(), ["--info=stats2"]);
        assert_eq!(modern.name_listing_args(), ["--info=name2"]);
        assert_eq!(modern.resume_args(), ["--partial", "--append-verify"]);
        assert_eq!(modern.no_motd_args(), ["--no-motd"]);
        assert_eq!(
            modern.compression_args(7),
            ["--compress-choice=zstd", "--compress-level=7"]
        );
        assert_eq!(
            modern.compression_args(19),
            ["--compress-choice=zstd", "--compress-level=19"]
        );
        assert!(modern.compression_args(0).is_empty());

        let legacy = RsyncCapabilities::LEGACY;
        assert_eq!(legacy.progress_args(), ["--progress"]);
        assert_eq!(legacy.stats_args(), ["--stats"]);
        assert_eq!(legacy.name_listing_args(), ["-vv"]);
        assert_eq!(legacy.resume_args(), ["--partial"]);
        assert!(legacy.no_motd_args().is_empty());
        assert_eq!(legacy.compression_args(7), ["--compress-level=7"]);
        // zlib tops out at 9; a zstd-tuned level must not be passed through.
        assert_eq!(legacy.compression_args(19), ["--compress-level=9"]);
        assert!(legacy.compression_args(0).is_empty());

        let openrsync = RsyncFlavor::OpenRsync { protocol: Some(29) }.capabilities();
        assert_eq!(openrsync.no_motd_args(), ["--no-motd"]);
        assert_eq!(openrsync.progress_args(), ["--progress"]);
    }

    #[test]
    fn display_and_describe() {
        assert_eq!(
            RsyncFlavor::Rsync {
                major: 3,
                minor: 4,
                patch: 1
            }
            .to_string(),
            "rsync 3.4.1"
        );
        assert_eq!(
            RsyncFlavor::OpenRsync { protocol: Some(29) }.to_string(),
            "openrsync (protocol 29)"
        );
        let resolved = ResolvedRsync {
            path: PathBuf::from("/opt/homebrew/bin/rsync"),
            flavor: RsyncFlavor::Rsync {
                major: 3,
                minor: 4,
                patch: 1,
            },
            version_line: "rsync  version 3.4.1  protocol version 32".to_string(),
            source: RsyncSource::PreferredLocation,
            shadowed: Some(ShadowedRsync {
                path: PathBuf::from("/usr/bin/rsync"),
                flavor: RsyncFlavor::OpenRsync { protocol: Some(29) },
            }),
        };
        assert_eq!(
            resolved.describe(),
            "rsync 3.4.1 at /opt/homebrew/bin/rsync (well-known install location); \
             PATH rsync is openrsync (protocol 29) at /usr/bin/rsync"
        );
    }

    #[test]
    fn override_path_expands_tilde_and_keeps_absolute_paths() {
        assert_eq!(
            override_path("/usr/bin/rsync"),
            Some(PathBuf::from("/usr/bin/rsync"))
        );
        let home = override_path("~/bin/rsync").expect("expanded");
        assert!(!home.to_string_lossy().starts_with('~'));
        assert!(home.ends_with("bin/rsync"));
        assert_eq!(override_path("   "), None);
    }

    #[test]
    fn explicit_override_to_missing_binary_is_an_error() {
        let missing =
            std::env::temp_dir().join(format!("rch-rsync-missing-{}", uuid::Uuid::new_v4()));
        let error = resolve_rsync(Some(missing.to_str().expect("utf-8"))).expect_err("missing");
        assert_eq!(
            error,
            RsyncResolveError::OverrideMissing {
                origin: RsyncSource::Config,
                path: missing,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_override_is_honoured_whatever_its_flavour() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("rsync");
        std::fs::write(
            &fake,
            "#!/bin/sh\necho 'openrsync: protocol version 29'\necho 'rsync version 2.6.9 compatible'\n",
        )
        .expect("write");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let resolved = resolve_rsync(Some(fake.to_str().expect("utf-8"))).expect("resolved");
        assert_eq!(resolved.path, fake);
        assert_eq!(resolved.source, RsyncSource::Config);
        assert_eq!(
            resolved.flavor,
            RsyncFlavor::OpenRsync { protocol: Some(29) }
        );
        assert_eq!(resolved.version_line, "openrsync: protocol version 29");
        assert!(resolved.capabilities().is_compatibility_mode());
        assert!(resolved.shadowed.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn probe_reports_binaries_that_print_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let silent = dir.path().join("rsync");
        std::fs::write(&silent, "#!/bin/sh\nexit 0\n").expect("write");
        std::fs::set_permissions(&silent, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let error = probe_rsync_version(&silent).expect_err("silent");
        assert!(
            matches!(error, RsyncResolveError::ProbeFailed { reason, .. } if reason == "no version output")
        );
    }

    #[test]
    fn cached_resolution_is_stable_within_a_process() {
        clear_resolve_cache();
        let first = resolve_rsync_cached(None);
        let second = resolve_rsync_cached(None);
        assert_eq!(first, second);
        if let Ok(resolved) = first {
            assert!(resolved.path.is_absolute(), "{}", resolved.path.display());
            assert!(!resolved.version_line.is_empty());
        }
    }
}
