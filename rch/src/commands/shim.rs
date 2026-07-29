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

/// Whether `shim_dir` appears before `~/.cargo/bin` in `PATH` (required for the
/// shim to actually intercept `cargo`).
fn shim_dir_precedes_cargo_bin(dir: &Path) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let cargo_bin = dirs::home_dir().map(|h| h.join(".cargo").join("bin"));
    for entry in std::env::split_paths(&path) {
        if entry == dir {
            return true;
        }
        if let Some(cb) = &cargo_bin
            && &entry == cb
        {
            // Hit ~/.cargo/bin first → the rustup cargo wins.
            return false;
        }
    }
    false
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
    on_path_ahead_of_cargo: bool,
    local_builds_running: Option<usize>,
}

/// `rch shim install` — write (or refresh) the canonical cargo shim.
pub fn shim_install(require_remote: bool, ctx: &OutputContext) -> Result<()> {
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

    let ahead = shim_dir_precedes_cargo_bin(&shim_dir()?);

    if ctx.is_json() {
        let status = ShimStatus {
            installed: true,
            path: path.display().to_string(),
            version: Some(SHIM_VERSION.to_string()),
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date: true,
            on_path_ahead_of_cargo: ahead,
            local_builds_running: local_build_process_count(),
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
    if !ahead {
        let dir = shim_dir()?;
        println!(
            "\n{} The shim is not yet ahead of ~/.cargo/bin on PATH. Add this to your shell rc:",
            StatusIndicator::Warning.display(style)
        );
        println!("    export PATH=\"{}:$PATH\"", dir.display());
        println!("  then restart your shells (or `hash -r`).");
    } else {
        println!(
            "  {} PATH already resolves this shim ahead of ~/.cargo/bin.",
            StatusIndicator::Info.display(style)
        );
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
    let ahead = installed && shim_dir_precedes_cargo_bin(&shim_dir()?);
    let local_builds = local_build_process_count();

    if ctx.is_json() {
        let status = ShimStatus {
            installed,
            path: path.display().to_string(),
            version,
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date,
            on_path_ahead_of_cargo: ahead,
            local_builds_running: local_builds,
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
    if ahead {
        println!(
            "  {} PATH resolves the shim ahead of ~/.cargo/bin",
            StatusIndicator::Info.display(style)
        );
    } else {
        println!(
            "  {} PATH does NOT resolve the shim first — cargo is not being intercepted",
            StatusIndicator::Warning.display(style)
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
                "  {} {n} local rustc running — builds are compiling on this box (check PATH order / absolute-path `.rustup/.../bin/cargo` invocations)",
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
    if !path.exists() {
        if !ctx.is_json() {
            println!(
                "{} cargo shim not installed; nothing to remove.",
                StatusIndicator::Info.display(style)
            );
        }
        return Ok(());
    }
    std::fs::remove_file(&path)
        .with_context(|| format!("Failed to remove cargo shim at {}", path.display()))?;
    if ctx.is_json() {
        let status = ShimStatus {
            installed: false,
            path: path.display().to_string(),
            version: None,
            embedded_version: SHIM_VERSION.to_string(),
            up_to_date: false,
            on_path_ahead_of_cargo: false,
            local_builds_running: local_build_process_count(),
        };
        let _ = ctx.json(&status);
    } else {
        println!(
            "{} Removed cargo shim at {}",
            StatusIndicator::Success.display(style),
            style.highlight(&path.display().to_string())
        );
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
}
