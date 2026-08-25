//! Cargo shim management (`rch shim install|status|uninstall`).
//!
//! rch auto-intercepts builds via the Claude Code PreToolUse hook, but that only
//! covers Claude Code. Codex, plain shells, scripts, and CI invoke `cargo`
//! directly — with no hook to catch them — so their builds run locally on the
//! box, defeating the whole point of rch on an orchestrator/dispatcher.
//!
//! rch already honors a cargo-wrapper contract: when it re-execs cargo on local
//! fallback it sets `RCH_CARGO_WRAPPER_BYPASS=1` (see [`crate::hook`]). It just
//! never shipped the wrapper, so every box hand-rolled one (or had none). This
//! command installs the ONE canonical wrapper, so every agent offloads.
//!
//! The shim is deliberately conservative:
//! - loop-safe: honors `RCH_CARGO_WRAPPER_BYPASS=1` (rch's own re-exec) → real cargo;
//! - fail-open: if `rch` is not on `PATH`, run the real cargo unchanged;
//! - IDE-safe: any `--message-format*` arg (rust-analyzer) → real cargo, local;
//! - only the artifact/test subcommands are offloaded; everything else is local.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::state::primitives::atomic_write;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;

/// Bumped whenever the embedded shim body changes so `shim status` can detect a
/// stale on-disk copy and prompt a reinstall.
const SHIM_VERSION: &str = "1";

/// Marker line embedded in the generated shim, used to recognize an rch-managed
/// file (vs. a hand-rolled or unrelated `cargo` on `PATH`) and read its version.
const SHIM_MARKER: &str = "# rch-shim-version:";

/// Directory the shim is installed into. Deliberately NOT `~/.local/bin` (which
/// `acfs`/installers manage and could clobber) — a dedicated dir rch owns.
fn shim_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".rch").join("shims"))
        .context("Could not determine home directory")
}

/// Path to the installed cargo shim.
fn cargo_shim_path() -> Result<PathBuf> {
    Ok(shim_dir()?.join("cargo"))
}

/// Render the canonical cargo shim.
///
/// `require_remote` bakes fail-closed (queue-for-a-worker, never local rustc)
/// vs. fail-open (attempt offload, fall back to local under load) into the file.
/// A dispatcher box wants fail-closed; that is the default on install.
fn cargo_shim_body(require_remote: bool) -> String {
    // The offload line differs only by the strict-remote policy. Keeping the
    // rest identical makes drift detection a simple version-marker check.
    let offload = if require_remote {
        // Fail-closed: queue for a worker, never fall back to local rustc.
        "exec env RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- cargo \"$@\""
    } else {
        // Fail-open: attempt offload but allow local fallback (rch default).
        "exec rch exec -- cargo \"$@\""
    };
    format!(
        r##"#!/bin/sh
# rch cargo shim — MANAGED FILE, edit via `rch shim install`.
{marker} {version}
#
# Harness-agnostic build offload: any agent (codex/scripts/CI, not only Claude
# Code) that runs `cargo build|test|check|...` is routed through `rch exec` to
# the worker fleet instead of compiling locally on this box. See `rch shim`.
REAL="${{RCH_SHIM_REAL_CARGO:-$HOME/.cargo/bin/cargo}}"
# Loop-break: rch sets RCH_CARGO_WRAPPER_BYPASS=1 on its own local-fallback exec.
# Also fail open if rch is unavailable — never block a build.
if [ "${{RCH_CARGO_WRAPPER_BYPASS:-}}" = "1" ] || ! command -v rch >/dev/null 2>&1; then
  exec "$REAL" "$@"
fi
# Leave IDE/tooling (rust-analyzer) local: it needs streaming JSON + local state.
for a in "$@"; do
  case "$a" in --message-format*) exec "$REAL" "$@" ;; esac
done
case "${{1:-}}" in
  build|b|test|t|check|c|clippy|bench|doc|nextest)
    {offload} ;;
  *)
    exec "$REAL" "$@" ;;
esac
"##,
        marker = SHIM_MARKER,
        version = SHIM_VERSION,
        offload = offload,
    )
}

/// Read the `SHIM_VERSION` recorded in an installed shim, if it is rch-managed.
fn installed_shim_version(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix(SHIM_MARKER)
            .map(|v| v.trim().to_string())
    })
}

/// How `cargo` actually resolves on this box right now.
///
/// Comparing raw `PATH` order against `shim_dir` is not sufficient: installers
/// (and rch's own docs) legitimately place a *delegating* `cargo` earlier on
/// `PATH` — a tiny script whose only job is to `exec` the canonical shim. That
/// still intercepts, so reporting "not intercepted" for it is a false alarm
/// that sends operators off reordering `PATH` for no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Interception {
    /// `PATH` resolves straight to the rch shim.
    Direct,
    /// `PATH` resolves to a wrapper that delegates to the rch shim.
    Delegated,
    /// `PATH` resolves to a real cargo binary — builds run locally.
    None,
}

impl Interception {
    fn intercepts(self) -> bool {
        matches!(self, Self::Direct | Self::Delegated)
    }
}

/// True if `path` is a small text file that hands off to the rch shim.
///
/// Deliberately content-based rather than name-based: the delegating wrapper is
/// written by installers we do not control, so the only reliable signal is that
/// it references the shim we own.
fn delegates_to_shim(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    // A real cargo is megabytes; a delegating shell wrapper is a few hundred
    // bytes. Bail early so we never slurp a binary.
    if meta.len() > 8 * 1024 {
        return false;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.contains(".rch/shims/cargo") || content.contains(SHIM_MARKER)
}

/// Resolve the first `cargo` on `PATH` and classify it.
fn cargo_interception(shim: &Path) -> Interception {
    let Some(path) = std::env::var_os("PATH") else {
        return Interception::None;
    };
    for entry in std::env::split_paths(&path) {
        // POSIX treats an empty PATH entry as "$PWD". Honoring that here would
        // make the verdict depend on the directory rch happens to be run from
        // (a stray ./cargo would be read as the resolved cargo), so skip it —
        // a cwd-relative hit is never what this check is meant to report on.
        if entry.as_os_str().is_empty() {
            continue;
        }
        let candidate = entry.join("cargo");
        if !candidate.is_file() {
            continue;
        }
        // First cargo on PATH decides — everything after it is shadowed.
        if candidate == shim {
            return Interception::Direct;
        }
        if delegates_to_shim(&candidate) {
            return Interception::Delegated;
        }
        return Interception::None;
    }
    Interception::None
}

// ---------------------------------------------------------------------------
// Toolchain wrapping
//
// The PATH shim only catches PATH lookups. Scripts, Makefiles, build drivers
// and agents routinely invoke `~/.rustup/toolchains/<tc>/bin/cargo` by ABSOLUTE
// path (rustup's own `cargo +nightly ...` re-exec does too), which bypasses
// PATH entirely. Wrapping the toolchain binary itself is the one layer an
// absolute-path call cannot dodge, so `shim install` does it too.
//
// Mechanism, per toolchain:
//   cargo           -> wrapper script (delegates to the canonical shim)
//   cargo-rch-real  -> the original binary, preserved by hardlinking it first
// Linking (rather than moving) the original means `cargo` never stops existing
// for even an instant, copies no bytes, and leaves the code signature intact.
// The swap-in is an atomic rename, so a concurrent exec sees either the old or
// the new file, never a missing one. (After the rename the two names no longer
// share a link count: `cargo` is the new wrapper inode and `cargo-rch-real` is
// the sole remaining name for the original inode — which is the point.)
// ---------------------------------------------------------------------------

/// Bumped whenever the toolchain wrapper body changes.
///
/// Version `1` is also what the predecessor `wrap_toolchain_cargo.sh` emitted,
/// and hosts wrapped by that script are already in the field. The two bodies are
/// behaviourally identical (same bypass check, same shim handoff, same
/// `RCH_SHIM_REAL_CARGO` export) and differ only in a comment, so they
/// legitimately share a version and `install` leaves them alone. Bump this the
/// moment the body changes semantically, which will also converge those hosts.
const TOOLCHAIN_WRAP_VERSION: &str = "1";

/// Marker identifying an rch-managed toolchain wrapper (vs. the real binary).
const TOOLCHAIN_MARKER: &str = "# rch-toolchain-wrap-version:";

/// Filename the original toolchain cargo is preserved under.
const REAL_CARGO_NAME: &str = "cargo-rch-real";

/// `~/.rustup/toolchains`, honoring `RUSTUP_HOME`.
fn rustup_toolchains_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Some(PathBuf::from(home).join("toolchains"));
    }
    dirs::home_dir().map(|h| h.join(".rustup").join("toolchains"))
}

/// Every installed toolchain's `bin/cargo`, sorted for stable output.
fn toolchain_cargos() -> Vec<PathBuf> {
    let Some(root) = rustup_toolchains_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path().join("bin").join("cargo"))
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    out
}

/// Render the toolchain wrapper.
///
/// `$0` is the toolchain's own `bin/cargo`, so the wrapper can find its sibling
/// `cargo-rch-real` without hardcoding a toolchain name. Exporting
/// `RCH_SHIM_REAL_CARGO` preserves *toolchain identity* through any local
/// fallback — otherwise rch's fallback would silently build with the rustup
/// default toolchain instead of the one the caller explicitly asked for.
fn toolchain_wrap_body() -> String {
    format!(
        r##"#!/bin/sh
# rch toolchain cargo wrapper — MANAGED FILE, edit via `rch shim install`.
{marker} {version}
#
# Routes ABSOLUTE-path toolchain cargo calls through the canonical rch shim.
# Scripts/Makefiles/agents invoking ~/.rustup/toolchains/<tc>/bin/cargo directly
# bypass PATH; this is the one layer they cannot dodge.
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REAL="$SELF_DIR/{real}"
SHIM="$HOME/.rch/shims/cargo"
# Loop-break + fail-open: rch sets RCH_CARGO_WRAPPER_BYPASS=1 on its own local
# fallback exec. Never block a build if the shim or rch is missing.
if [ "${{RCH_CARGO_WRAPPER_BYPASS:-}}" = "1" ] || [ ! -x "$SHIM" ] || ! command -v rch >/dev/null 2>&1; then
  exec "$REAL" "$@"
fi
# Preserve toolchain identity through any local fallback.
RCH_SHIM_REAL_CARGO="$REAL"
export RCH_SHIM_REAL_CARGO
exec "$SHIM" "$@"
"##,
        marker = TOOLCHAIN_MARKER,
        version = TOOLCHAIN_WRAP_VERSION,
        real = REAL_CARGO_NAME,
    )
}

/// Version recorded in an installed toolchain wrapper, if it is rch-managed.
fn toolchain_wrap_version(path: &Path) -> Option<String> {
    // Only ever read small files; a real cargo binary is megabytes.
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > 8 * 1024 {
        return None;
    }
    let content = std::fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix(TOOLCHAIN_MARKER)
            .map(|v| v.trim().to_string())
    })
}

fn is_toolchain_wrapped(path: &Path) -> bool {
    toolchain_wrap_version(path).is_some()
}

/// Outcome of wrapping a single toolchain, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapOutcome {
    Wrapped,
    Refreshed,
    AlreadyCurrent,
}

/// Wrap one toolchain's `cargo`.
#[cfg(unix)]
fn wrap_toolchain_cargo(cargo: &Path) -> Result<WrapOutcome> {
    use std::os::unix::fs::PermissionsExt;

    let dir = cargo
        .parent()
        .context("toolchain cargo has no parent directory")?;
    let real = dir.join(REAL_CARGO_NAME);

    if let Some(v) = toolchain_wrap_version(cargo) {
        if v == TOOLCHAIN_WRAP_VERSION && real.exists() {
            return Ok(WrapOutcome::AlreadyCurrent);
        }
        // Wrapper present but stale (or its real binary vanished): rewrite the
        // wrapper in place. `real` is already the original, so do NOT re-link
        // from `cargo` — that would hardlink the wrapper onto itself.
        if !real.exists() {
            anyhow::bail!(
                "{} is an rch wrapper but {} is missing — cannot recover the real cargo; \
                 reinstall this toolchain with `rustup toolchain install --force`",
                cargo.display(),
                real.display()
            );
        }
        atomic_write(cargo, toolchain_wrap_body().as_bytes())
            .with_context(|| format!("Failed to refresh wrapper at {}", cargo.display()))?;
        let mut perms = std::fs::metadata(cargo)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(cargo, perms)?;
        return Ok(WrapOutcome::Refreshed);
    }

    // `cargo` is the real binary here. A leftover `cargo-rch-real` means rustup
    // replaced the toolchain after a previous wrap; drop the stale copy so we
    // preserve the NEW binary rather than resurrecting the old one.
    if real.exists() {
        std::fs::remove_file(&real).with_context(|| {
            format!("Failed to remove stale real cargo at {}", real.display())
        })?;
    }
    std::fs::hard_link(cargo, &real).with_context(|| {
        format!(
            "Failed to hardlink {} -> {}",
            cargo.display(),
            real.display()
        )
    })?;
    // Guard the TOCTOU window: if a concurrent `shim install` swapped in its
    // wrapper between our not-wrapped check and this link, we just preserved a
    // WRAPPER as the "real" cargo — and writing our wrapper over `cargo` next
    // would destroy the toolchain's only real binary. Undo and fail loudly
    // instead; the other run already did the work correctly.
    if is_toolchain_wrapped(&real) {
        let _ = std::fs::remove_file(&real);
        anyhow::bail!(
            "concurrent wrap detected for {}: refusing to preserve a wrapper as the real cargo",
            cargo.display()
        );
    }
    // Atomic rename over `cargo`; a concurrent exec sees old or new, never gone.
    if let Err(e) = atomic_write(cargo, toolchain_wrap_body().as_bytes()) {
        // Roll back so the toolchain is never left without its real cargo.
        let _ = std::fs::remove_file(&real);
        return Err(e).with_context(|| format!("Failed to write wrapper at {}", cargo.display()));
    }
    let mut perms = std::fs::metadata(cargo)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(cargo, perms)?;
    Ok(WrapOutcome::Wrapped)
}

#[cfg(not(unix))]
fn wrap_toolchain_cargo(_cargo: &Path) -> Result<WrapOutcome> {
    anyhow::bail!("toolchain wrapping is only supported on Unix")
}

/// Restore one toolchain's original `cargo`.
fn unwrap_toolchain_cargo(cargo: &Path) -> Result<bool> {
    if !is_toolchain_wrapped(cargo) {
        return Ok(false);
    }
    let dir = cargo
        .parent()
        .context("toolchain cargo has no parent directory")?;
    let real = dir.join(REAL_CARGO_NAME);
    if !real.exists() {
        anyhow::bail!(
            "refusing to remove wrapper at {}: {} is missing (no real cargo to restore)",
            cargo.display(),
            real.display()
        );
    }
    std::fs::rename(&real, cargo)
        .with_context(|| format!("Failed to restore real cargo at {}", cargo.display()))?;
    Ok(true)
}

/// Wrapped/total counts across all installed toolchains.
fn toolchain_wrap_counts() -> (usize, usize) {
    let cargos = toolchain_cargos();
    let wrapped = cargos.iter().filter(|c| is_toolchain_wrapped(c)).count();
    (wrapped, cargos.len())
}

/// Count `rustc`/`cargo` processes running on this box right now (best-effort,
/// Unix only). A dispatcher with the shim working should see ~0 (aside from
/// rust-analyzer's short-lived probes).
#[cfg(unix)]
fn local_build_process_count() -> Option<usize> {
    let out = std::process::Command::new("pgrep")
        .args(["-x", "rustc"])
        .output()
        .ok()?;
    if !out.status.success() && out.stdout.is_empty() {
        return Some(0);
    }
    Some(
        out.stdout
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count(),
    )
}

#[cfg(not(unix))]
fn local_build_process_count() -> Option<usize> {
    None
}

/// Machine-readable result for `--json`.
#[derive(Debug, Serialize)]
struct ShimStatus {
    installed: bool,
    path: String,
    version: Option<String>,
    embedded_version: String,
    up_to_date: bool,
    /// Kept for compatibility: true when `cargo` resolves to the shim by any
    /// route (directly or via a delegating wrapper).
    on_path_ahead_of_cargo: bool,
    /// How `cargo` actually resolves: direct / delegated / none.
    interception: Interception,
    local_builds_running: Option<usize>,
    /// Rustup toolchains whose `bin/cargo` is wrapped, and the total installed.
    toolchains_wrapped: usize,
    toolchains_total: usize,
    /// Per-toolchain failures from the last wrap/unwrap attempt. Without this a
    /// `--json` consumer sees `wrapped < total` with no way to learn why, which
    /// matters because this output is meant for agents.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    toolchain_errors: Vec<String>,
}

/// `rch shim install` — write (or refresh) the canonical cargo shim, and wrap
/// the rustup toolchain cargos so absolute-path invocations are caught too.
pub fn shim_install(require_remote: bool, wrap_toolchains: bool, ctx: &OutputContext) -> Result<()> {
    // bd-wywsj: a WORKER box is the compute — shimming cargo to
    // offload from it is a configuration error, refused loudly.
    if let Ok(config) = crate::config::load_config()
        && config.general.role == rch_common::BoxRole::Worker
    {
        anyhow::bail!(
            "refusing to install the cargo shim: general.role = \"worker\" — this box IS \
             the compute. Set role = \"dispatcher\" or \"hybrid\" in config.toml if this \
             machine should offload builds."
        );
    }
    let style = ctx.theme();
    let path = cargo_shim_path()?;
    let body = cargo_shim_body(require_remote);

    let existed = path.exists();
    atomic_write(&path, body.as_bytes())
        .with_context(|| format!("Failed to write cargo shim to {}", path.display()))?;
    // atomic_write does not preserve mode; make it executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)?;
    }

    // Wrap the rustup toolchains too — the PATH shim alone cannot catch an
    // absolute-path `~/.rustup/toolchains/<tc>/bin/cargo` invocation, which is
    // how scripts, Makefiles and `cargo +toolchain` re-execs reach cargo.
    let mut wrapped_now = 0usize;
    let mut refreshed = 0usize;
    let mut already = 0usize;
    let mut wrap_errors: Vec<String> = Vec::new();
    if wrap_toolchains {
        for cargo in toolchain_cargos() {
            match wrap_toolchain_cargo(&cargo) {
                Ok(WrapOutcome::Wrapped) => wrapped_now += 1,
                Ok(WrapOutcome::Refreshed) => refreshed += 1,
                Ok(WrapOutcome::AlreadyCurrent) => already += 1,
                // One bad toolchain must not abort the rest; report and move on.
                Err(e) => wrap_errors.push(format!("{}: {e:#}", cargo.display())),
            }
        }
    }

    let interception = cargo_interception(&path);
    let ahead = interception.intercepts();
    let (tc_wrapped, tc_total) = toolchain_wrap_counts();

    if ctx.is_json() {
        let status = ShimStatus {
            installed: true,
            path: path.display().to_string(),
            version: Some(SHIM_VERSION.to_string()),
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date: true,
            on_path_ahead_of_cargo: ahead,
            interception,
            local_builds_running: local_build_process_count(),
            toolchains_wrapped: tc_wrapped,
            toolchains_total: tc_total,
            toolchain_errors: wrap_errors.clone(),
        };
        let _ = ctx.json(&status);
        return Ok(());
    }

    println!(
        "{} {} cargo shim at {}",
        StatusIndicator::Success.display(style),
        if existed { "Updated" } else { "Installed" },
        style.highlight(&path.display().to_string())
    );
    println!(
        "  policy: {}",
        if require_remote {
            "fail-closed (queue for a worker; never build locally)"
        } else {
            "fail-open (offload, but fall back to local under load)"
        }
    );
    if wrap_toolchains {
        if tc_total == 0 {
            println!(
                "  {} no rustup toolchains found to wrap",
                StatusIndicator::Info.display(style)
            );
        } else {
            println!(
                "  {} toolchains: {tc_wrapped}/{tc_total} wrapped ({wrapped_now} new, {refreshed} refreshed, {already} already current)",
                StatusIndicator::Success.display(style)
            );
        }
        for err in &wrap_errors {
            println!("  {} {err}", StatusIndicator::Warning.display(style));
        }
    }

    match interception {
        Interception::None => {
            let dir = shim_dir()?;
            println!(
                "\n{} The shim is not yet ahead of ~/.cargo/bin on PATH. Add this to your shell rc:",
                StatusIndicator::Warning.display(style)
            );
            println!("    export PATH=\"{}:$PATH\"", dir.display());
            println!("  then restart your shells (or `hash -r`).");
            if tc_wrapped > 0 {
                println!(
                    "  {} toolchain wrappers still catch absolute-path cargo calls meanwhile.",
                    StatusIndicator::Info.display(style)
                );
            }
        }
        Interception::Direct => println!(
            "  {} PATH already resolves this shim ahead of ~/.cargo/bin.",
            StatusIndicator::Info.display(style)
        ),
        Interception::Delegated => println!(
            "  {} PATH resolves a wrapper that delegates to this shim — cargo is intercepted.",
            StatusIndicator::Info.display(style)
        ),
    }
    Ok(())
}

/// `rch shim status` — report install state, version drift, PATH order, and any
/// local builds currently running.
pub fn shim_status(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let path = cargo_shim_path()?;
    let installed = path.exists();
    let version = if installed {
        installed_shim_version(&path)
    } else {
        None
    };
    let up_to_date = version.as_deref() == Some(SHIM_VERSION);
    let interception = if installed {
        cargo_interception(&path)
    } else {
        Interception::None
    };
    let ahead = interception.intercepts();
    let local_builds = local_build_process_count();
    let (tc_wrapped, tc_total) = toolchain_wrap_counts();

    if ctx.is_json() {
        let status = ShimStatus {
            installed,
            path: path.display().to_string(),
            version,
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date,
            on_path_ahead_of_cargo: ahead,
            interception,
            local_builds_running: local_builds,
            toolchains_wrapped: tc_wrapped,
            toolchains_total: tc_total,
            // `status` never mutates, so it has no failures of its own.
            toolchain_errors: Vec::new(),
        };
        let _ = ctx.json(&status);
        return Ok(());
    }

    if !installed {
        println!(
            "{} cargo shim not installed. Run `rch shim install`.",
            StatusIndicator::Warning.display(style)
        );
        return Ok(());
    }
    println!(
        "{} cargo shim installed at {}",
        StatusIndicator::Success.display(style),
        style.highlight(&path.display().to_string())
    );
    if up_to_date {
        println!("  version: {SHIM_VERSION} (current)");
    } else {
        println!(
            "  {} version: {} (embedded {SHIM_VERSION}) — run `rch shim install` to refresh",
            StatusIndicator::Warning.display(style),
            version.as_deref().unwrap_or("unknown")
        );
    }
    match interception {
        Interception::Direct => println!(
            "  {} PATH resolves the shim ahead of ~/.cargo/bin",
            StatusIndicator::Info.display(style)
        ),
        Interception::Delegated => println!(
            "  {} PATH resolves a wrapper that delegates to this shim — cargo IS intercepted",
            StatusIndicator::Info.display(style)
        ),
        Interception::None => println!(
            "  {} PATH does NOT resolve the shim first — cargo is not being intercepted",
            StatusIndicator::Warning.display(style)
        ),
    }
    if tc_total == 0 {
        println!(
            "  {} no rustup toolchains installed",
            StatusIndicator::Info.display(style)
        );
    } else if tc_wrapped == tc_total {
        println!(
            "  {} toolchains: {tc_wrapped}/{tc_total} wrapped (absolute-path cargo is intercepted)",
            StatusIndicator::Info.display(style)
        );
    } else {
        println!(
            "  {} toolchains: {tc_wrapped}/{tc_total} wrapped — {} unwrapped toolchain(s) can still build locally via absolute path; run `rch shim install`",
            StatusIndicator::Warning.display(style),
            tc_total - tc_wrapped
        );
    }
    if let Some(n) = local_builds {
        if n == 0 {
            println!(
                "  {} no local rustc running",
                StatusIndicator::Info.display(style)
            );
        } else {
            println!(
                "  {} {n} local rustc running — builds are compiling on this box (check PATH order / unwrapped toolchains above)",
                StatusIndicator::Warning.display(style)
            );
        }
    }
    Ok(())
}

/// `rch shim uninstall` — remove the cargo shim.
pub fn shim_uninstall(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let path = cargo_shim_path()?;

    // Always restore toolchains, even if the PATH shim is already gone —
    // otherwise a half-uninstalled box keeps wrappers pointing at a missing
    // shim. (They fail open, but leaving them is still a surprise.)
    let mut restored = 0usize;
    let mut unwrap_errors: Vec<String> = Vec::new();
    for cargo in toolchain_cargos() {
        match unwrap_toolchain_cargo(&cargo) {
            Ok(true) => restored += 1,
            Ok(false) => {}
            Err(e) => unwrap_errors.push(format!("{}: {e:#}", cargo.display())),
        }
    }

    let had_shim = path.exists();
    if had_shim {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove cargo shim at {}", path.display()))?;
    }

    if ctx.is_json() {
        let (tc_wrapped, tc_total) = toolchain_wrap_counts();
        let status = ShimStatus {
            installed: false,
            path: path.display().to_string(),
            version: None,
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date: false,
            on_path_ahead_of_cargo: false,
            interception: Interception::None,
            local_builds_running: local_build_process_count(),
            toolchains_wrapped: tc_wrapped,
            toolchains_total: tc_total,
            toolchain_errors: unwrap_errors.clone(),
        };
        let _ = ctx.json(&status);
        return Ok(());
    }

    if had_shim {
        println!(
            "{} Removed cargo shim at {}",
            StatusIndicator::Success.display(style),
            style.highlight(&path.display().to_string())
        );
    } else {
        println!(
            "{} cargo shim not installed; nothing to remove.",
            StatusIndicator::Info.display(style)
        );
    }
    if restored > 0 {
        println!(
            "  {} restored {restored} toolchain cargo binaries",
            StatusIndicator::Success.display(style)
        );
    }
    for err in &unwrap_errors {
        println!("  {} {err}", StatusIndicator::Warning.display(style));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_body_is_loop_safe_and_fail_open() {
        let body = cargo_shim_body(true);
        // Honors rch's own bypass and the missing-rch case up front.
        assert!(body.contains("RCH_CARGO_WRAPPER_BYPASS"));
        assert!(body.contains("command -v rch"));
        // rust-analyzer's JSON checks stay local.
        assert!(body.contains("--message-format"));
        // Offload set present.
        assert!(body.contains("build|b|test|t|check|c|clippy|bench|doc|nextest"));
        // Version marker present and parseable.
        assert_eq!(
            installed_shim_version_from_str(&body).as_deref(),
            Some(SHIM_VERSION)
        );
    }

    #[test]
    fn require_remote_toggles_fail_closed() {
        let closed = cargo_shim_body(true);
        let open = cargo_shim_body(false);
        assert!(closed.contains("RCH_REQUIRE_REMOTE=1"));
        assert!(closed.contains("RCH_QUEUE_WHEN_BUSY=1"));
        assert!(!open.contains("RCH_REQUIRE_REMOTE=1"));
        assert!(open.contains("rch exec -- cargo"));
    }

    #[test]
    fn shim_only_offloads_build_subcommands() {
        let body = cargo_shim_body(true);
        // The catch-all arm runs the real cargo for everything else.
        assert!(body.contains("*)\n    exec \"$REAL\" \"$@\" ;;"));
    }

    // Test helper mirroring installed_shim_version over an in-memory string.
    fn installed_shim_version_from_str(body: &str) -> Option<String> {
        body.lines().find_map(|line| {
            line.trim()
                .strip_prefix(SHIM_MARKER)
                .map(|v| v.trim().to_string())
        })
    }

    // --- toolchain wrapping -------------------------------------------------

    #[test]
    fn toolchain_wrapper_is_loop_safe_and_fail_open() {
        let body = toolchain_wrap_body();
        // Same loop-break contract rch honors on its own local-fallback exec.
        assert!(body.contains("RCH_CARGO_WRAPPER_BYPASS"));
        // Fail open when the shim is absent or rch is not installed.
        assert!(body.contains(r#"[ ! -x "$SHIM" ]"#));
        assert!(body.contains("command -v rch"));
        // Toolchain identity must survive a local fallback, else rch would
        // rebuild with the rustup default rather than the requested toolchain.
        assert!(body.contains("RCH_SHIM_REAL_CARGO=\"$REAL\""));
        assert!(body.contains("export RCH_SHIM_REAL_CARGO"));
        // Resolves its sibling real binary relative to $0, not a hardcoded path.
        assert!(body.contains(r#"SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"#));
        assert!(body.contains(REAL_CARGO_NAME));
    }

    #[test]
    fn toolchain_wrapper_version_is_detectable() {
        let body = toolchain_wrap_body();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cargo");
        std::fs::write(&p, &body).unwrap();
        assert_eq!(
            toolchain_wrap_version(&p).as_deref(),
            Some(TOOLCHAIN_WRAP_VERSION)
        );
        assert!(is_toolchain_wrapped(&p));
    }

    #[test]
    fn a_real_cargo_binary_is_not_mistaken_for_a_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cargo");
        // Oversized, non-UTF8 payload: stands in for a real multi-MB binary.
        std::fs::write(&p, vec![0u8; 16 * 1024]).unwrap();
        assert!(!is_toolchain_wrapped(&p));
        assert!(!delegates_to_shim(&p));
    }

    #[cfg(unix)]
    #[test]
    fn wrap_then_unwrap_restores_the_original_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        let original = b"#!/bin/sh\necho i-am-the-real-cargo\n";
        std::fs::write(&cargo, original).unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(wrap_toolchain_cargo(&cargo).unwrap(), WrapOutcome::Wrapped);
        assert!(is_toolchain_wrapped(&cargo));
        // The real binary is preserved beside it, byte-for-byte.
        let real = bin.join(REAL_CARGO_NAME);
        assert_eq!(std::fs::read(&real).unwrap(), original);
        // Wrapper must be executable or every build breaks.
        assert_eq!(
            std::fs::metadata(&cargo).unwrap().permissions().mode() & 0o111,
            0o111
        );

        // Idempotent: a second install is a no-op, not a double-wrap.
        assert_eq!(
            wrap_toolchain_cargo(&cargo).unwrap(),
            WrapOutcome::AlreadyCurrent
        );
        assert_eq!(std::fs::read(&real).unwrap(), original);

        assert!(unwrap_toolchain_cargo(&cargo).unwrap());
        assert_eq!(std::fs::read(&cargo).unwrap(), original);
        assert!(!real.exists());
        // Unwrapping an already-plain cargo is a no-op, not an error.
        assert!(!unwrap_toolchain_cargo(&cargo).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn rustup_replacing_a_toolchain_rewraps_the_new_binary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        std::fs::write(&cargo, b"old-cargo").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        wrap_toolchain_cargo(&cargo).unwrap();

        // rustup overwrites `cargo` with a fresh binary, leaving the stale
        // `cargo-rch-real` behind. The new binary must win.
        std::fs::write(&cargo, b"new-cargo-from-rustup").unwrap();
        assert_eq!(wrap_toolchain_cargo(&cargo).unwrap(), WrapOutcome::Wrapped);
        assert_eq!(
            std::fs::read(bin.join(REAL_CARGO_NAME)).unwrap(),
            b"new-cargo-from-rustup"
        );
        assert!(unwrap_toolchain_cargo(&cargo).unwrap());
        assert_eq!(std::fs::read(&cargo).unwrap(), b"new-cargo-from-rustup");
    }

    #[cfg(unix)]
    #[test]
    fn unwrap_refuses_when_the_real_binary_is_missing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        std::fs::write(&cargo, b"real").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        wrap_toolchain_cargo(&cargo).unwrap();
        std::fs::remove_file(bin.join(REAL_CARGO_NAME)).unwrap();
        // Deleting the wrapper here would destroy cargo entirely.
        assert!(unwrap_toolchain_cargo(&cargo).is_err());
        assert!(cargo.exists());
    }

    // --- interception classification ---------------------------------------

    #[cfg(unix)]
    #[test]
    fn concurrent_wrap_never_preserves_a_wrapper_as_the_real_cargo() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        // Simulate losing the race: `cargo` is already another run's wrapper,
        // but no `cargo-rch-real` exists yet, so the not-wrapped path would
        // otherwise link the wrapper over itself and lose the real binary.
        // (is_toolchain_wrapped is true here, so we take the refresh path and
        // must refuse because the real binary is absent.)
        std::fs::write(&cargo, toolchain_wrap_body()).unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(wrap_toolchain_cargo(&cargo).is_err());
        // cargo is untouched, and nothing bogus was left behind.
        assert!(is_toolchain_wrapped(&cargo));
        assert!(!bin.join(REAL_CARGO_NAME).exists());
    }

    #[test]
    fn empty_path_entries_do_not_resolve_cargo_from_cwd() {
        // A stray ./cargo must not decide the verdict just because PATH has an
        // empty component. Directly exercises the guard in cargo_interception.
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("shims").join("cargo");
        std::fs::create_dir_all(shim.parent().unwrap()).unwrap();
        std::fs::write(&shim, cargo_shim_body(true)).unwrap();
        // PATH = ":<shimdir>" — leading empty entry, then the real shim dir.
        let joined = std::env::join_paths([
            std::path::PathBuf::new(),
            shim.parent().unwrap().to_path_buf(),
        ])
        .unwrap();
        // SAFETY: single-threaded test process mutating its own env.
        unsafe { std::env::set_var("PATH", &joined) };
        assert_eq!(cargo_interception(&shim), Interception::Direct);
    }

    #[test]
    fn delegating_wrapper_counts_as_interception() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cargo");
        std::fs::write(
            &p,
            b"#!/bin/sh\nSHIM=\"$HOME/.rch/shims/cargo\"\nexec \"$SHIM\" \"$@\"\n",
        )
        .unwrap();
        assert!(delegates_to_shim(&p));
    }

    #[test]
    fn interception_intercepts_predicate() {
        assert!(Interception::Direct.intercepts());
        assert!(Interception::Delegated.intercepts());
        assert!(!Interception::None.intercepts());
    }
}
