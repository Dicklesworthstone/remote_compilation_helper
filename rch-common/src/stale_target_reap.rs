//! Shared predicate + shell-snippet builder for reaping *stale* per-job remote
//! `CARGO_TARGET_DIR` directories.
//!
//! rch gives every forwarded-`CARGO_TARGET_DIR` build a per-job target dir named
//! `.rch-target-<worker>-job-<id>-<ts>-<seq>` (or `…-pid-<pid>-…`). Such a dir can
//! stay in active use far beyond a single command — a long-running build keeps
//! writing into it (one was observed accumulating ~11.5h of artifacts). So a
//! per-job dir must **never** be removed merely because some build finished; that
//! could clip a build still in flight. Instead we remove only dirs that have seen
//! **no file activity for `idle_hours`** — i.e. finished/abandoned ones. A dir idle
//! that long cannot be a live job (an active build touches its dir continuously),
//! so reaping never races a concurrent build on the same project, even when
//! multiple agents build it on the same worker at once.
//!
//! This logic is shared by two callers so the predicate cannot drift:
//!
//! 1. The **orchestrator hook** reaper
//!    (`rch::transfer::TransferPipeline::reap_stale_sibling_per_job_target_dirs`),
//!    which runs as a side-effect of an offloaded build and scans only the single
//!    project dir being built on the chosen worker.
//! 2. The **daemon-side worker sweep** (`rchd::stale_target_reap`), a periodic
//!    background task that scans *every* project dir under the worker's
//!    `remote_base` so orphaned dirs in repos nobody is currently building still
//!    get reclaimed.
//!
//! Both share [`is_safe_reap_path`] / [`is_safe_reap_token`] (the security
//! boundary — inputs are embedded into the generated shell) and
//! [`reap_loop_body`] (the per-dir staleness test + removal). The matched glob is
//! always exactly `.rch-target-*-job-*` / `.rch-target-*-pid-*` — never a bare
//! `target`, never a source dir, never `.git`/`.beads`.

/// The glob patterns matched for reaping. Restricted to per-job/per-pid dirs so a
/// bare `target` (or any non-rch dir) is never touched.
pub const REAP_GLOBS: &[&str] = &[".rch-target-*-job-*", ".rch-target-*-pid-*"];

/// Whether `s` is safe to use as a `cd` target / `find` root of a reap script:
/// absolute, at least two path segments deep (never `/` or a bare top-level dir),
/// no `..`, and composed only of unambiguous path characters (no shell
/// metacharacters, quotes, spaces, or globs).
///
/// This is the security boundary: reap inputs are embedded into a generated shell
/// command (inside double quotes), so anything that could break out of that
/// context, escape the intended scope, or traverse upward is rejected.
pub fn is_safe_reap_path(s: &str) -> bool {
    s.starts_with('/')
        && s.matches('/').count() >= 2
        && !s.contains("..")
        && s.len() <= 4096
        && s.chars().all(is_safe_reap_char)
}

/// Whether `s` is safe to use as a *base* directory of a reap script (the
/// worker's `remote_base`, e.g. `/tmp/rch`). Looser than [`is_safe_reap_path`]
/// only in that it permits a single path segment (e.g. `/srv`), but still rejects
/// the filesystem root, `..`, and shell metacharacters.
pub fn is_safe_reap_base(s: &str) -> bool {
    s.starts_with('/')
        && s.matches('/').count() >= 1
        && s.trim_end_matches('/').len() > 1
        && !s.contains("..")
        && s.len() <= 4096
        && s.chars().all(is_safe_reap_char)
}

/// Whether `s` is safe to embed as a directory basename token in a reap script
/// (e.g. the current job's dir name, used to exclude it from reaping).
pub fn is_safe_reap_token(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.contains('/')
        && s.len() <= 255
        && s.chars().all(is_safe_reap_char)
}

/// The only characters permitted in reap-script path inputs. Excludes every shell
/// metacharacter (quotes, `$`, backtick, `*`, spaces, `;`, `|`, `&`, …) so the
/// inputs cannot break out of their double-quoted context.
pub fn is_safe_reap_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')
}

/// Floor (in hours) below which the idle threshold is never allowed to drop,
/// regardless of configuration — so a misconfiguration can never reap a live
/// incremental cache. Mirrors the hook's `stale_target_reap_idle_hours` floor.
pub const MIN_IDLE_HOURS: u32 = 1;

/// Convert an `idle_hours` setting to the `find -mmin` window used by the reap
/// predicate, applying the 1h floor.
pub fn idle_minutes_from_hours(idle_hours: u32) -> u64 {
    u64::from(idle_hours.max(MIN_IDLE_HOURS)) * 60
}

/// The shared per-dir reap predicate + removal, as a `sh` loop body operating on a
/// loop variable `$d` (a candidate dir path or basename, already confirmed to be a
/// directory by the caller's loop).
///
/// For each candidate it keeps the dir if the dir **or any descendant** (file or
/// subdir) was modified within the idle window — an active or just-`mkdir`'d build
/// — and otherwise `rm -rf`s it. `-mmin -N -print -quit` stops at the first recent
/// entry, so live dirs are detected cheaply. Deliberately **no** `-type f`: an
/// empty, just-created dir (a concurrent build's target before its first write)
/// has zero files but a recent dir mtime and must be kept.
///
/// `idle_minutes` is the window; `exclude_token`, when `Some`, is a basename to
/// skip (the orchestrator's own current job dir). `removed_counter` / `freed_kb`
/// are shell variable names the body increments so callers can emit metrics
/// (pass empty strings to skip accounting). The body assumes `$d` holds the
/// candidate path and does **not** itself iterate.
pub fn reap_loop_body(
    idle_minutes: u64,
    exclude_token: Option<&str>,
    removed_counter: &str,
    freed_kb: &str,
) -> String {
    let exclude = match exclude_token {
        Some(tok) => format!("[ \"$d\" = \"{tok}\" ] && continue; "),
        None => String::new(),
    };
    // Account for size only when both counter var names are provided.
    let (size_capture, removal) = if removed_counter.is_empty() || freed_kb.is_empty() {
        (
            String::new(),
            "rm -rf -- \"$d\" 2>/dev/null;".to_string(),
        )
    } else {
        (
            "sz=$(du -sk \"$d\" 2>/dev/null | awk '{print $1}'); [ -z \"$sz\" ] && sz=0; ".to_string(),
            format!(
                "if rm -rf -- \"$d\" 2>/dev/null; then {removed_counter}=$(({removed_counter} + 1)); {freed_kb}=$(({freed_kb} + sz)); fi;"
            ),
        )
    };
    format!(
        "[ -d \"$d\" ] || continue; \
         {exclude}\
         if find \"$d\" -mmin -{idle_minutes} -print -quit 2>/dev/null | grep -q .; then continue; fi; \
         {size_capture}{removal}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_reap_path_accepts_deep_abs() {
        assert!(is_safe_reap_path("/tmp/rch/myproject/abc123"));
        assert!(is_safe_reap_path("/tmp/rch"));
    }

    #[test]
    fn safe_reap_path_rejects_dangerous() {
        assert!(!is_safe_reap_path("/"));
        assert!(!is_safe_reap_path("/tmp")); // only one segment
        assert!(!is_safe_reap_path("/tmp/../etc"));
        assert!(!is_safe_reap_path("/tmp/rch; rm -rf x"));
        assert!(!is_safe_reap_path("relative/path"));
        assert!(!is_safe_reap_path("/tmp/$(whoami)"));
    }

    #[test]
    fn safe_reap_base_allows_single_segment_but_not_root() {
        assert!(is_safe_reap_base("/srv"));
        assert!(is_safe_reap_base("/tmp/rch"));
        assert!(!is_safe_reap_base("/"));
        assert!(!is_safe_reap_base("//"));
        assert!(!is_safe_reap_base("/../x"));
    }

    #[test]
    fn safe_reap_token_rules() {
        assert!(is_safe_reap_token(".rch-target-ts2-job-1-2-0"));
        assert!(!is_safe_reap_token(""));
        assert!(!is_safe_reap_token("."));
        assert!(!is_safe_reap_token(".."));
        assert!(!is_safe_reap_token("a/b"));
        assert!(!is_safe_reap_token("a b"));
    }

    #[test]
    fn idle_minutes_floor() {
        assert_eq!(idle_minutes_from_hours(0), 60);
        assert_eq!(idle_minutes_from_hours(12), 720);
    }

    #[test]
    fn loop_body_keeps_recent_and_excludes_current() {
        let body = reap_loop_body(720, Some(".rch-target-self"), "", "");
        // Excludes the current job dir.
        assert!(body.contains("[ \"$d\" = \".rch-target-self\" ] && continue"));
        // Keeps dirs with recent activity (no -type f).
        assert!(body.contains("find \"$d\" -mmin -720 -print -quit"));
        assert!(!body.contains("-type f"));
        // Removes otherwise.
        assert!(body.contains("rm -rf -- \"$d\""));
    }

    #[test]
    fn loop_body_with_metrics_accounts_size() {
        let body = reap_loop_body(720, None, "removed", "freed_kb");
        assert!(body.contains("du -sk \"$d\""));
        assert!(body.contains("removed=$((removed + 1))"));
        assert!(body.contains("freed_kb=$((freed_kb + sz))"));
    }
}
