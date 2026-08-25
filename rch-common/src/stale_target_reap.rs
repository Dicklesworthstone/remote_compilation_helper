//! Shared predicate + shell-snippet builder for reaping *stale* per-job remote
//! `CARGO_TARGET_DIR` directories.
//!
//! rch gives every forwarded-`CARGO_TARGET_DIR` build a target dir named either
//! `.rch-target-<worker>-job-<id>-<ts>-<seq>` (per-job, the legacy/opt-out name;
//! also `…-pid-<pid>-…`) or `.rch-target-<worker>-pool-<key>` (the default
//! REUSED-across-jobs pooled dir keyed by build dimensions). Such a dir can
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
//! always exactly `.rch-target-*-job-*` / `.rch-target-*-pid-*` / `.rch-target-*-pool-*`
//! — never a bare `target`, never a source dir, never `.git`/`.beads`.
//!
//! Pooled dirs (`-pool-`) are SHARED by concurrent jobs with identical build
//! dimensions, but the idle-based predicate still reaps them safely: an actively
//! building pool dir has a fresh mtime (cargo writes into it continuously), so it
//! is never evicted while in use, and once every job sharing it has finished it
//! goes idle like any per-job dir and is reclaimed after `idle_hours`.

/// The glob patterns matched for reaping. Restricted to per-job / per-pid /
/// pooled dirs so a bare `target` (or any non-rch dir) is never touched.
pub const REAP_GLOBS: &[&str] = &[
    ".rch-target-*-job-*",
    ".rch-target-*-pid-*",
    ".rch-target-*-pool-*",
];

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
    reap_loop_body_with_event(idle_minutes, exclude_token, removed_counter, freed_kb, None)
}

/// [`reap_loop_body`] with an optional per-removal EVENT line: when `trigger`
/// is `Some` (and counters are enabled), every successful removal prints
/// `RCH_REAP_RM <kb> <trigger> <path>` so a reviewer can reconstruct any
/// deletion — which dir, how big, which policy removed it — from the sweep
/// output alone (bead 6dj11's observability requirement; also the
/// diagnosability gap named in bd-kwvy8).
pub fn reap_loop_body_with_event(
    idle_minutes: u64,
    exclude_token: Option<&str>,
    removed_counter: &str,
    freed_kb: &str,
    trigger: Option<&str>,
) -> String {
    let exclude = match exclude_token {
        Some(tok) => format!("[ \"$d\" = \"{tok}\" ] && continue; "),
        None => String::new(),
    };
    // Account for size only when both counter var names are provided.
    let (size_capture, removal) = if removed_counter.is_empty() || freed_kb.is_empty() {
        (String::new(), "rm -rf -- \"$d\" 2>/dev/null;".to_string())
    } else {
        // Tagged (sweep) contexts capture rm's stderr instead of silencing it
        // (bd-kwvy8: a half-removed dir with removed=0 was undiagnosable
        // because the failing rm was 2>/dev/null'd) — a failed removal emits
        // `RCH_REAP_ERR <trigger> <path> :: <first stderr line>`.
        let removal_body = match trigger {
            Some(tag) => format!(
                "if __rmerr=$(rm -rf -- \"$d\" 2>&1); then \
                   {removed_counter}=$(({removed_counter} + 1)); {freed_kb}=$(({freed_kb} + sz)); \
                   printf 'RCH_REAP_RM %s {tag} %s\\n' \"$sz\" \"$d\"; \
                 else \
                   printf 'RCH_REAP_ERR {tag} %s :: %s\\n' \"$d\" \"$(printf '%s' \"$__rmerr\" | head -1)\"; \
                 fi;"
            ),
            None => format!(
                "if rm -rf -- \"$d\" 2>/dev/null; then {removed_counter}=$(({removed_counter} + 1)); {freed_kb}=$(({freed_kb} + sz)); fi;"
            ),
        };
        (
            "sz=$(du -sk \"$d\" 2>/dev/null | awk '{print $1}'); [ -z \"$sz\" ] && sz=0; "
                .to_string(),
            removal_body,
        )
    };
    format!(
        "[ -d \"$d\" ] || continue; \
         {exclude}\
         if find \"$d\" -mmin -{idle_minutes} -print -quit 2>/dev/null | grep -q .; then continue; fi; \
         {size_capture}{removal}"
    )
}

/// The shared candidate-discovery preamble for worker-wide sweeps: canonicalize
/// `$base` (already validated by [`is_safe_reap_base`]), refuse shallow roots,
/// and write every candidate dir path into `$__tmpf` — the per-job/per-pid
/// `.rch-target-*` dirs at any depth under `$base`, plus the LEGACY
/// `rch_target_*` trees directly under the worker's tmp base (bead 6dj11: the
/// 2026-07-10 css incident class, which nothing else reaps). The tmp base is
/// `$TMPDIR` when set, else `/data/tmp`, else `/tmp`, and the legacy pass is
/// gated on it being at least two segments deep so a bare `/tmp` fallback is
/// deliberately never scanned (mirrors the `$base` depth guard).
///
/// `on_guard_exit` is the `sh` fragment run before `exit 0` on every guard
/// bail-out (e.g. printing an empty metrics line so callers always parse a
/// result). The `find … > file` + `while read … < file` shape (instead of a
/// pipe) keeps the caller's loop in the parent shell so counters survive.
/// Depth to scan under the worker's tmp base for dot-prefixed reap-class dirs.
///
/// rch stages pooled/per-job targets at
/// `<tmpbase>/rch/<project>/<hash>/.rch-target-<worker>-{pool,job,pid}-<key>`,
/// i.e. THREE levels below the tmp base — outside the sync-root (`$__rt`)
/// walk that every other pass uses. Before this, only the depth-1
/// `rch_target_*` legacy pass looked at the tmp base at all, so those trees
/// were never reaped and grew to 110-129 GB per worker while `rch gc`
/// truthfully reported "removed 0 dir(s), freed 0 MB". Six leaves headroom
/// for a deeper stage layout without turning the walk into a full-tree scan.
const TMPBASE_MAXDEPTH: u32 = 6;

/// Emit an in-place dedup of the candidate list held in `$<var>` that can never
/// truncate it.
///
/// The tmp-base pass can rediscover a dir the `$base` pass already listed (when
/// the sync root sits under the tmp base), and a duplicate would be counted
/// twice in the byte-cap pass's `total_kb`, over-evicting warm caches. The
/// obvious `sort -u F -o F` is safe with GNU sort on a healthy filesystem — but
/// this sweep runs precisely when a disk is FULL, and a sort that fails after
/// opening its output would leave the candidate list empty, so gc would reap
/// nothing exactly when it is needed most. Sorting into a fresh temp and moving
/// it over only on success keeps the original list intact on any failure; the
/// cost of a failed dedup is a duplicate entry, which the reap loop already
/// tolerates via its leading `[ -d "$d" ] || continue`.
fn dedup_candidate_file(var: &str) -> String {
    format!(
        "if __ded=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null); then \
           if sort -u \"${var}\" -o \"$__ded\" 2>/dev/null; then mv -f \"$__ded\" \"${var}\"; \
           else rm -f \"$__ded\"; fi; \
         fi; "
    )
}

fn candidate_discovery_preamble(escaped_base: &str, on_guard_exit: &str) -> String {
    format!(
        "set -u; \
         base=\"{escaped_base}\"; \
         if [ ! -d \"$base\" ]; then {on_guard_exit}exit 0; fi; \
         __rt=$(cd \"$base\" 2>/dev/null && pwd -P) || {{ {on_guard_exit}exit 0; }}; \
         [ -n \"$__rt\" ] || {{ {on_guard_exit}exit 0; }}; \
         case \"$__rt\" in */*/*) ;; *) {on_guard_exit}exit 0;; esac; \
         __tmpbase=\"${{TMPDIR:-}}\"; \
         [ -n \"$__tmpbase\" ] && [ -d \"$__tmpbase\" ] || __tmpbase=/data/tmp; \
         [ -d \"$__tmpbase\" ] || __tmpbase=/tmp; \
         __tmpf=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null) || {{ {on_guard_exit}exit 0; }}; \
         find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune 2>/dev/null > \"$__tmpf\"; \
         case \"$__tmpbase\" in /*/*) find \"$__tmpbase\" -maxdepth 1 -type d -name \"rch_target_*\" -prune 2>/dev/null >> \"$__tmpf\"; \
           find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune 2>/dev/null >> \"$__tmpf\";; esac; \
         {dedup}",
        dedup = dedup_candidate_file("__tmpf")
    )
}

/// Minimum non-zero pooled idle window in minutes (24h). Pooled dirs are warm
/// caches; the builder floors any smaller non-zero window to this as a last
/// defense behind the config-level validation.
pub const MIN_POOLED_IDLE_MINUTES: u64 = 24 * 60;

/// Build the worker-wide sweep script shared by the daemon's periodic reaper
/// (`rchd::stale_target_reap`) and the on-demand `rch gc` — one builder so the
/// two can never drift (bead 6dj11). Applies [`reap_loop_body`] to every
/// candidate from [`candidate_discovery_preamble`] and always prints a final
/// `RCH_WORKER_REAP_METRICS removed=<n> freed_kb=<kb>` line.
///
/// `pooled_idle_minutes` adds a SECOND pass over the pooled
/// `.rch-target-*-pool-*` dirs with its own (much longer) idle window —
/// `None` skips pooled dirs entirely. Pooled dirs are reused warm caches, so
/// they only reap after e.g. seven idle days (a pool key nobody has built for
/// a week is a corpse, not a cache); non-zero windows are floored at
/// [`MIN_POOLED_IDLE_MINUTES`]. Same counters, same predicate, one metrics
/// line covering both passes.
///
/// `escaped_base` MUST already be validated with [`is_safe_reap_base`]; it is
/// embedded inside double quotes.
#[must_use]
pub fn worker_sweep_command(
    escaped_base: &str,
    idle_minutes: u64,
    pooled_idle_minutes: Option<u64>,
    max_cache_kb: Option<u64>,
) -> String {
    let loop_body =
        reap_loop_body_with_event(idle_minutes, None, "removed", "freed_kb", Some("ttl"));
    let guard = "printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; ";
    let preamble = candidate_discovery_preamble(escaped_base, guard);
    let pooled_pass = match pooled_idle_minutes {
        Some(window) => {
            let window = window.max(MIN_POOLED_IDLE_MINUTES);
            let pooled_body =
                reap_loop_body_with_event(window, None, "removed", "freed_kb", Some("pooled-ttl"));
            let dedup2 = dedup_candidate_file("__tmpf2");
            format!(
                "if __tmpf2=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null); then \
                   find \"$__rt\" -maxdepth 8 -type d -name \".rch-target-*-pool-*\" -prune 2>/dev/null > \"$__tmpf2\"; \
                   case \"$__tmpbase\" in /*/*) find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d -name \".rch-target-*-pool-*\" -prune 2>/dev/null >> \"$__tmpf2\";; esac; \
                   {dedup2}\
                   while IFS= read -r d; do {pooled_body} done < \"$__tmpf2\"; \
                   rm -f \"$__tmpf2\"; \
                 fi; "
            )
        }
        None => String::new(),
    };
    // Byte-cap eviction (bead 6dj11): after the TTL passes, when the TOTAL of
    // every remaining reap-class dir exceeds the budget, evict oldest first —
    // but NEVER a dir with activity within the short idle window (the same
    // whole-tree `find -mmin` active-build safety floor as the TTL pass) —
    // until back under. Oldest-first makes this a warm-LRU by construction:
    // the newest warm pools survive, the coldest go first. Ordering uses the
    // dir's own mtime via `date -r` (portable across GNU/BSD, and cargo
    // touches the target root constantly during builds, so it is a good
    // recency proxy — the `-mmin` tree walk remains the safety authority);
    // sizes come from `du -sk`. The candidate list is re-discovered because
    // the TTL passes just removed entries; `sort -n` orders oldest-mtime
    // first; the eviction loop reads from a FILE so the counter mutations
    // survive (no pipe subshell).
    let dedup3 = dedup_candidate_file("__tmpf3");
    let cap_pass = match max_cache_kb {
        Some(cap_kb) => format!(
            "if [ {cap_kb} -gt 0 ] \
               && __lst=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null) \
               && __tmpf3=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null); then \
               find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" -o -name \".rch-target-*-pool-*\" \\) -prune 2>/dev/null > \"$__tmpf3\"; \
               case \"$__tmpbase\" in /*/*) find \"$__tmpbase\" -maxdepth 1 -type d -name \"rch_target_*\" -prune 2>/dev/null >> \"$__tmpf3\"; \
                 find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" -o -name \".rch-target-*-pool-*\" \\) -prune 2>/dev/null >> \"$__tmpf3\";; esac; \
               {dedup3}\
               : > \"$__lst\"; total_kb=0; \
               while IFS= read -r d; do \
                 [ -d \"$d\" ] || continue; \
                 __n=$(date -r \"$d\" +%s 2>/dev/null); [ -n \"$__n\" ] || __n=0; \
                 __k=$(du -sk \"$d\" 2>/dev/null | awk '{{print $1}}'); [ -n \"$__k\" ] || __k=0; \
                 total_kb=$((total_kb + __k)); \
                 printf '%s %s %s\\n' \"$__n\" \"$__k\" \"$d\" >> \"$__lst\"; \
               done < \"$__tmpf3\"; \
               if [ \"$total_kb\" -gt {cap_kb} ]; then \
                 printf 'RCH_REAP_CAP initial_kb=%s cap_kb={cap_kb}\\n' \"$total_kb\"; \
                 sort -n \"$__lst\" > \"$__tmpf3\"; \
                 while IFS=' ' read -r __n __k d; do \
                   [ \"$total_kb\" -le {cap_kb} ] && break; \
                   [ -d \"$d\" ] || continue; \
                   if find \"$d\" -mmin -{idle_minutes} -print -quit 2>/dev/null | grep -q .; then \
                     printf 'RCH_REAP_SKIP cap %s active %s\\n' \"$__k\" \"$d\"; continue; \
                   fi; \
                   if __rmerr=$(rm -rf -- \"$d\" 2>&1); then \
                     removed=$((removed + 1)); freed_kb=$((freed_kb + __k)); total_kb=$((total_kb - __k)); \
                     printf 'RCH_REAP_RM %s cap %s\\n' \"$__k\" \"$d\"; \
                   else \
                     printf 'RCH_REAP_ERR cap %s :: %s\\n' \"$d\" \"$(printf '%s' \"$__rmerr\" | head -1)\"; \
                   fi; \
                 done < \"$__tmpf3\"; \
                 printf 'RCH_REAP_CAP final_kb=%s\\n' \"$total_kb\"; \
               fi; \
               rm -f \"$__lst\" \"$__tmpf3\"; \
             fi; "
        ),
        None => String::new(),
    };
    format!(
        "{preamble}\
         removed=0; freed_kb=0; \
         while IFS= read -r d; do {loop_body} done < \"$__tmpf\"; \
         rm -f \"$__tmpf\"; \
         {pooled_pass}\
         {cap_pass}\
         printf 'RCH_WORKER_REAP_METRICS removed=%s freed_kb=%s\\n' \"$removed\" \"$freed_kb\""
    )
}

/// Parse the `RCH_WORKER_REAP_METRICS removed=<n> freed_kb=<kb>` line a
/// [`worker_sweep_command`] run prints. Returns `(removed, freed_kb)`.
#[must_use]
pub fn parse_worker_reap_metrics(stdout: &str) -> Option<(u64, u64)> {
    let line = stdout
        .lines()
        .find(|l| l.contains("RCH_WORKER_REAP_METRICS"))?;
    let mut removed = None;
    let mut freed_kb = None;
    for token in line.split_whitespace().skip(1) {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "removed" => removed = value.parse::<u64>().ok(),
            "freed_kb" => freed_kb = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    Some((removed.unwrap_or(0), freed_kb.unwrap_or(0)))
}

/// One per-removal event from a [`worker_sweep_command`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapEvent {
    /// Disk usage of the removed dir in KiB.
    pub kb: u64,
    /// Which policy removed it: `ttl`, `pooled-ttl`, or `cap`.
    pub trigger: String,
    /// Absolute path removed.
    pub path: String,
}

/// Parse the `RCH_REAP_RM <kb> <trigger> <path>` event lines a
/// [`worker_sweep_command`] run prints — one per successful removal, so any
/// deletion can be reconstructed from the output alone. Unparseable lines are
/// skipped.
#[must_use]
pub fn parse_reap_events(stdout: &str) -> Vec<ReapEvent> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("RCH_REAP_RM ")?;
            let mut parts = rest.splitn(3, ' ');
            let kb = parts.next()?.parse::<u64>().ok()?;
            let trigger = parts.next()?.to_string();
            let path = parts.next()?.trim();
            if path.is_empty() {
                return None;
            }
            Some(ReapEvent {
                kb,
                trigger,
                path: path.to_string(),
            })
        })
        .collect()
}

/// One failed-removal diagnostic from a [`worker_sweep_command`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapError {
    /// Which pass hit the failure: `ttl`, `pooled-ttl`, or `cap`.
    pub trigger: String,
    /// Path whose removal failed.
    pub path: String,
    /// First line of `rm`'s stderr.
    pub message: String,
}

/// Parse the `RCH_REAP_ERR <trigger> <path> :: <message>` lines a
/// [`worker_sweep_command`] run prints — one per FAILED removal (bd-kwvy8:
/// silenced rm failures made a half-removed dir undiagnosable). Unparseable
/// lines are skipped.
#[must_use]
pub fn parse_reap_errors(stdout: &str) -> Vec<ReapError> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("RCH_REAP_ERR ")?;
            let (trigger, rest) = rest.split_once(' ')?;
            let (path, message) = rest.split_once(" :: ")?;
            if path.is_empty() {
                return None;
            }
            Some(ReapError {
                trigger: trigger.to_string(),
                path: path.to_string(),
                message: message.trim().to_string(),
            })
        })
        .collect()
}

/// Build the READ-ONLY enumeration script behind `rch cache status` and
/// `rch gc --dry-run`: identical candidate discovery to
/// [`worker_sweep_command`] (so what status shows is exactly what gc would
/// consider), plus the POOLED `.rch-target-*-pool-*` dirs — deliberately NOT
/// swept (they are reused across jobs) but usually the largest disk consumers,
/// so observability must include them. Nothing is removed. One line per
/// candidate:
///
/// `RCH_TARGET_ENTRY <newest_mtime_unix> <kb> <path>`
///
/// `newest_mtime_unix` is the newest mtime of the dir or any descendant (the
/// exact signal the idle predicate tests) and `<kb>` the apparent-size sum,
/// both from ONE `find -printf '%T@ %s'` + awk pass per dir (GNU find —
/// workers are Linux by contract). A du-based variant needed three stat walks
/// and exceeded 15 minutes live on a loaded worker whose pooled dirs held
/// millions of inodes; apparent size instead of block usage is an acceptable
/// trade for an observability surface. `escaped_base` MUST already be
/// validated with [`is_safe_reap_base`].
#[must_use]
pub fn enumerate_targets_command(escaped_base: &str) -> String {
    let preamble = candidate_discovery_preamble(escaped_base, "");
    // Pooled dirs are appended AFTER the preamble, so they need the tmp-base
    // pass and a second dedup of their own: what `rch gc --dry-run` lists must
    // be exactly what `worker_sweep_command` would act on, and the sweep's
    // pooled pass reaches the tmp base. Without this the dry run would omit
    // precisely the dirs the real run reaps.
    let dedup = dedup_candidate_file("__tmpf");
    format!(
        "{preamble}\
         find \"$__rt\" -maxdepth 8 -type d -name \".rch-target-*-pool-*\" -prune 2>/dev/null >> \"$__tmpf\"; \
         case \"$__tmpbase\" in /*/*) find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d -name \".rch-target-*-pool-*\" -prune 2>/dev/null >> \"$__tmpf\";; esac; \
         {dedup}\
         while IFS= read -r d; do \
           [ -d \"$d\" ] || continue; \
           set -- $(find \"$d\" -printf '%T@ %s\\n' 2>/dev/null | awk '{{ t=int($1); if (t>n) n=t; s+=$2 }} END {{ printf \"%d %d\", n, int(s/1024) }}'); \
           newest=${{1:-0}}; kb=${{2:-0}}; \
           printf 'RCH_TARGET_ENTRY %s %s %s\\n' \"$newest\" \"$kb\" \"$d\"; \
         done < \"$__tmpf\"; \
         rm -f \"$__tmpf\""
    )
}

/// One enumerated remote target dir from [`enumerate_targets_command`] output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTargetEntry {
    /// Newest mtime (Unix seconds) of the dir or any descendant.
    pub newest_mtime_unix: u64,
    /// Disk usage in KiB (`du -sk`).
    pub kb: u64,
    /// Absolute path on the worker.
    pub path: String,
}

impl RemoteTargetEntry {
    /// Whether this is a pooled (`-pool-`) dir — reused across jobs, shown for
    /// observability but never swept by gc.
    #[must_use]
    pub fn is_pooled(&self) -> bool {
        self.path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(".rch-target-") && name.contains("-pool-"))
    }
}

/// Parse the `RCH_TARGET_ENTRY` lines an [`enumerate_targets_command`] run
/// prints. Unparseable lines are skipped (fail-open observability).
#[must_use]
pub fn parse_target_entries(stdout: &str) -> Vec<RemoteTargetEntry> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("RCH_TARGET_ENTRY ")?;
            let mut parts = rest.splitn(3, ' ');
            let newest_mtime_unix = parts.next()?.parse::<u64>().ok()?;
            let kb = parts.next()?.parse::<u64>().ok()?;
            let path = parts.next()?.trim();
            if path.is_empty() {
                return None;
            }
            Some(RemoteTargetEntry {
                newest_mtime_unix,
                kb,
                path: path.to_string(),
            })
        })
        .collect()
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

    /// Pooled/per-job targets staged under the tmp base
    /// (`/data/tmp/rch/<project>/<hash>/.rch-target-<worker>-pool-<key>`) sit
    /// three levels below it and outside the sync-root walk, so before the
    /// tmp-base pass they were invisible to every discovery pass and grew to
    /// 110-129 GB per worker while gc reported "removed 0 dir(s)".
    #[test]
    fn tmp_base_dot_prefixed_targets_are_discovered() {
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), Some(1024));

        // Job/pid pass reaches the tmp base, not just depth-1 `rch_target_*`.
        assert!(cmd.contains(&format!(
            "find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\)"
        )));
        // Pooled pass reaches the tmp base too.
        assert!(cmd.contains(&format!(
            "find \"$__tmpbase\" -maxdepth {TMPBASE_MAXDEPTH} -type d -name \".rch-target-*-pool-*\""
        )));
        // The legacy depth-1 pass is retained, not replaced.
        assert!(cmd.contains("-maxdepth 1 -type d -name \"rch_target_*\""));
        // A base that is also under the tmp base can list a dir twice; dedup
        // keeps the byte-cap pass's total_kb honest.
        for var in ["__tmpf", "__tmpf2", "__tmpf3"] {
            assert!(
                cmd.contains(&format!("sort -u \"${var}\" -o \"$__ded\"")),
                "missing dedup for ${var}"
            );
            assert!(
                cmd.contains(&format!("mv -f \"$__ded\" \"${var}\"")),
                "dedup for ${var} must move the sorted temp back into place"
            );
        }
        // Dedup must NEVER sort a candidate list onto itself: gc runs on full
        // disks, and a sort that fails after opening its output would empty the
        // list exactly when gc is needed most.
        for var in ["__tmpf", "__tmpf2", "__tmpf3"] {
            assert!(
                !cmd.contains(&format!("sort -u \"${var}\" -o \"${var}\"")),
                "in-place sort of ${var} can truncate the candidate list"
            );
        }
    }

    /// The tmp-base walk stays behind the same two-segment guard as the sync
    /// root, so a bare `/tmp` fallback is never swept wholesale.
    #[test]
    fn tmp_base_passes_keep_shallow_root_guard() {
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), None);
        for pass in cmd.split("case \"$__tmpbase\" in").skip(1) {
            assert!(
                pass.starts_with(" /*/*)"),
                "tmp-base pass must keep the /*/* depth guard: {pass}"
            );
        }
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

    /// Minimal shell-style glob match (`*` = any run of chars) for asserting a
    /// dir name is covered by one of the `REAP_GLOBS`.
    fn glob_matches(glob: &str, name: &str) -> bool {
        // Split on `*` and require each literal segment to appear in order, with
        // the first/last anchored when the glob has no leading/trailing `*`.
        let parts: Vec<&str> = glob.split('*').collect();
        let mut pos = 0usize;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            match name[pos..].find(part) {
                Some(idx) => {
                    if i == 0 && !glob.starts_with('*') && idx != 0 {
                        return false;
                    }
                    pos += idx + part.len();
                }
                None => return false,
            }
        }
        // Trailing literal must end the name when glob doesn't end in `*`.
        if !glob.ends_with('*') {
            return name.ends_with(parts.last().copied().unwrap_or(""));
        }
        true
    }

    #[test]
    fn pooled_target_dir_name_is_reapable() {
        // The pooled remote target dir (`.rch-target-<worker>-pool-<key>`) minted
        // by the hook for target-dir REUSE must still be matched by a reap glob so
        // the existing idle-based reaper reclaims abandoned pools.
        let name = ".rch-target-ts2-pool-deadbeefcafef00ddeadbeefcafef00d";
        assert!(
            REAP_GLOBS.iter().any(|g| glob_matches(g, name)),
            "pooled target dir {name} must match a reap glob: {REAP_GLOBS:?}"
        );
        assert!(
            is_safe_reap_token(name),
            "pooled name must be reap-token-safe"
        );
        // The legacy per-job/per-pid names stay reapable too.
        assert!(
            REAP_GLOBS
                .iter()
                .any(|g| glob_matches(g, ".rch-target-ts2-job-7-123-0"))
        );
        assert!(
            REAP_GLOBS
                .iter()
                .any(|g| glob_matches(g, ".rch-target-ts2-pid-99-123-0"))
        );
        // A bare `target` (or non-rch dir) is NEVER matched.
        assert!(!REAP_GLOBS.iter().any(|g| glob_matches(g, "target")));
        assert!(!REAP_GLOBS.iter().any(|g| glob_matches(g, ".rch-target")));
    }

    #[test]
    fn worker_sweep_pooled_pass_is_optional_and_floored() {
        // Without a pooled window, pool dirs are never touched.
        let cmd = worker_sweep_command("/data/projects", 720, None, None);
        assert!(!cmd.contains("-pool-"));

        // With one, a second pass targets exactly the pool glob under its own
        // (floored) window, feeding the same counters.
        let cmd = worker_sweep_command("/data/projects", 720, Some(168 * 60), None);
        assert!(cmd.contains("-name \".rch-target-*-pool-*\" -prune"));
        assert!(
            cmd.contains("-mmin -10080"),
            "pooled window must reach the predicate"
        );
        assert!(cmd.contains("done < \"$__tmpf2\""));
        assert!(!cmd.contains("| while"));

        // A dangerously small non-zero window is floored to 24h.
        let cmd = worker_sweep_command("/data/projects", 720, Some(60), None);
        assert!(cmd.contains("-mmin -1440"));
    }

    #[test]
    fn worker_sweep_cap_pass_is_optional_and_shaped() {
        // Without a cap there is no accounting pass at all.
        let cmd = worker_sweep_command("/data/projects", 720, None, None);
        assert!(!cmd.contains("total_kb"));

        let cmd = worker_sweep_command("/data/projects", 720, None, Some(100 * 1024 * 1024));
        // The budget (KiB) reaches the comparison verbatim.
        assert!(cmd.contains("104857600"));
        // Oldest-first eviction order via numeric sort on newest-mtime.
        assert!(cmd.contains("sort -n"));
        // The active-build safety floor uses the SHORT idle window: once for
        // the TTL pass, once inside the eviction loop.
        assert!(cmd.matches("-mmin -720").count() >= 2);
        // Counter mutations survive: eviction loop reads from a file.
        assert!(cmd.contains("done < \"$__tmpf3\""));
        assert!(!cmd.contains("| while"));
    }

    #[test]
    fn worker_sweep_command_keeps_the_load_bearing_shape() {
        let cmd = worker_sweep_command("/data/projects", 720, None, None);
        // Per-job discovery is depth-bounded, pruned, and job/pid-only (pooled
        // dirs are reused and never swept).
        assert!(cmd.contains(
            "find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune"
        ));
        assert!(!cmd.contains("sweep-pool"));
        // 6dj11: the legacy tmp-base pass, depth-guarded so /tmp is never swept.
        assert!(cmd.contains(
            "case \"$__tmpbase\" in /*/*) find \"$__tmpbase\" -maxdepth 1 -type d -name \"rch_target_*\" -prune"
        ));
        // Metrics survive the loop: no `find | while` pipe subshell.
        assert!(cmd.contains("done < \"$__tmpf\""));
        assert!(!cmd.contains("| while"));
        assert!(cmd.contains("RCH_WORKER_REAP_METRICS removed=%s freed_kb=%s"));
        // The idle window (already minutes) reaches the predicate verbatim.
        assert!(cmd.contains("-mmin -720"));
    }

    #[test]
    fn enumerate_command_is_read_only_and_includes_pooled_dirs() {
        let cmd = enumerate_targets_command("/data/projects");
        assert!(cmd.contains("-name \".rch-target-*-pool-*\" -prune"));
        assert!(cmd.contains("RCH_TARGET_ENTRY"));
        assert!(cmd.contains("done < \"$__tmpf\""));
        // Read-only: never a recursive removal, and every `rm` targets a shell
        // temp-file variable this script created — never a discovered path.
        // (Stated as an invariant rather than an occurrence count so adding
        // temp bookkeeping cannot silently weaken it.)
        assert!(!cmd.contains("rm -rf"));
        let removals: Vec<&str> = cmd
            .match_indices("rm -f ")
            .map(|(i, _)| &cmd[i + "rm -f ".len()..])
            .collect();
        assert!(
            !removals.is_empty(),
            "enumerate should still clean up its temp files"
        );
        for tail in removals {
            assert!(
                tail.starts_with("\"$__"),
                "enumerate must only rm its own temp files, found: rm -f {}",
                &tail[..tail.len().min(40)]
            );
        }
        assert!(cmd.contains("rm -f \"$__tmpf\""));
    }

    /// The string-shape tests above cannot catch a malformed generated script.
    /// Actually RUN the sweep against a fixture and assert behaviour: a stale
    /// pool under the TMP BASE (the case that was invisible before) is reaped,
    /// a stale job dir under `$base` is reaped, and an ACTIVE dir in either
    /// location survives.
    #[cfg(unix)]
    #[test]
    fn worker_sweep_executes_and_reaps_only_idle_dirs() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("projects");
        let tmpbase = tmp.path().join("scratch");
        // Pools live 3 levels below the tmp base, mirroring the real layout:
        // <tmpbase>/rch/<project>/<hash>/.rch-target-<worker>-pool-<key>
        let stale_pool = tmpbase
            .join("rch")
            .join("proj")
            .join("hash")
            .join(".rch-target-w1-pool-deadbeef");
        let active_pool = tmpbase
            .join("rch")
            .join("proj2")
            .join("hash")
            .join(".rch-target-w1-pool-cafe");
        let stale_job = base.join("repo").join(".rch-target-w1-job-1-2-0");
        let active_job = base.join("repo").join(".rch-target-w1-job-9-9-9");
        for d in [&stale_pool, &active_pool, &stale_job, &active_job] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("artifact.o"), b"xxxx").unwrap();
        }

        // Age the stale ones well past the idle window. Whole-tree, because the
        // predicate is `find <dir> -mmin -N` over everything inside.
        for d in [&stale_pool, &stale_job] {
            let ok = Command::new("find")
                .arg(d)
                .args(["-exec", "touch", "-t", "202001010000", "{}", "+"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return; // no usable find/touch here; nothing to assert
            }
        }

        let cmd = worker_sweep_command(base.to_str().unwrap(), 60, Some(MIN_POOLED_IDLE_MINUTES), None);
        let out = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("TMPDIR", &tmpbase)
            .output()
            .expect("sweep should execute");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "generated sweep must be a valid script; stderr: {stderr}"
        );
        // A malformed script can still exit 0 while emitting syntax errors.
        assert!(
            !stderr.contains("syntax error") && !stderr.contains("unexpected"),
            "generated sweep emitted shell errors: {stderr}"
        );

        assert!(
            !stale_pool.exists(),
            "stale pool under the TMP BASE must be reaped (the regression this fixes)"
        );
        assert!(!stale_job.exists(), "stale job dir under $base must be reaped");
        assert!(active_pool.exists(), "recently-touched pool must survive");
        assert!(active_job.exists(), "recently-touched job dir must survive");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let (removed, _freed) =
            parse_worker_reap_metrics(&stdout).expect("sweep must print its metrics line");
        assert_eq!(removed, 2, "exactly the two idle dirs; stdout: {stdout}");
    }

    /// `rch gc --dry-run` enumerates; the real run sweeps. If enumerate cannot
    /// SEE a dir the sweep would reap, the dry run lies about what will happen.
    /// Both must cover the tmp base, for pooled dirs as well as job/pid dirs.
    #[cfg(unix)]
    #[test]
    fn enumerate_and_sweep_agree_on_tmp_base_discovery() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("projects");
        let tmpbase = tmp.path().join("scratch");
        let tmp_pool = tmpbase
            .join("rch")
            .join("proj")
            .join("hash")
            .join(".rch-target-w1-pool-abc");
        let base_pool = base.join("repo").join(".rch-target-w1-pool-def");
        let tmp_job = tmpbase
            .join("rch")
            .join("proj")
            .join("hash")
            .join(".rch-target-w1-job-1-2-0");
        for d in [&tmp_pool, &base_pool, &tmp_job] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("artifact.o"), b"xxxx").unwrap();
        }

        let cmd = enumerate_targets_command(base.to_str().unwrap());
        let out = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("TMPDIR", &tmpbase)
            .output()
            .expect("enumerate should execute");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "enumerate must be valid sh: {stderr}");
        assert!(
            !stderr.contains("syntax error") && !stderr.contains("unexpected"),
            "enumerate emitted shell errors: {stderr}"
        );

        let stdout = String::from_utf8_lossy(&out.stdout);
        let listed: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("RCH_TARGET_ENTRY "))
            .filter_map(|rest| rest.splitn(3, ' ').nth(2))
            .collect();

        for expected in [&tmp_pool, &base_pool, &tmp_job] {
            let want = expected.to_str().unwrap();
            assert!(
                listed.iter().any(|p| *p == want),
                "enumerate must list {want}; listed: {listed:?}"
            );
        }
        // Dedup must leave each dir exactly once, so the dry run cannot
        // double-report (and double-count KB) for a single directory.
        for want in &listed {
            assert_eq!(
                listed.iter().filter(|p| *p == want).count(),
                1,
                "duplicate entry for {want} in {listed:?}"
            );
        }
    }

    /// When the sync root sits UNDER the tmp base, both discovery passes match
    /// the same dirs. Without dedup the byte-cap pass would count them twice.
    #[cfg(unix)]
    #[test]
    fn overlapping_roots_are_deduped_not_double_counted() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        // base is INSIDE tmpbase: every candidate matches both finds.
        let tmpbase = tmp.path().join("scratch");
        let base = tmpbase.join("projects");
        let stale = base.join("repo").join(".rch-target-w1-job-1-2-0");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("artifact.o"), b"xxxx").unwrap();
        let aged = Command::new("find")
            .arg(&stale)
            .args(["-exec", "touch", "-t", "202001010000", "{}", "+"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !aged {
            return;
        }

        let cmd = worker_sweep_command(base.to_str().unwrap(), 60, Some(MIN_POOLED_IDLE_MINUTES), None);
        let out = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("TMPDIR", &tmpbase)
            .output()
            .expect("sweep should execute");
        assert!(out.status.success());

        let stdout = String::from_utf8_lossy(&out.stdout);
        let (removed, _) =
            parse_worker_reap_metrics(&stdout).expect("sweep must print its metrics line");
        assert!(!stale.exists(), "the stale dir should be reaped");
        assert_eq!(
            removed, 1,
            "a dir matched by both passes must be counted once; stdout: {stdout}"
        );
    }

    #[test]
    fn parse_worker_reap_metrics_roundtrips() {
        let out = "noise\nRCH_WORKER_REAP_METRICS removed=3 freed_kb=204800\n";
        assert_eq!(parse_worker_reap_metrics(out), Some((3, 204_800)));
        assert!(parse_worker_reap_metrics("no metrics here").is_none());
    }

    #[test]
    fn parse_target_entries_parses_and_skips_garbage() {
        let out = "RCH_TARGET_ENTRY 1754700000 1024 /data/tmp/rch_target_old\n\
                   garbage line\n\
                   RCH_TARGET_ENTRY notanum 5 /x\n\
                   RCH_TARGET_ENTRY 1754700001 2048 /data/projects/repo/.rch-target-css-pool-abc\n";
        let entries = parse_target_entries(out);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/data/tmp/rch_target_old");
        assert_eq!(entries[0].kb, 1024);
        assert!(!entries[0].is_pooled());
        assert!(entries[1].is_pooled());
    }

    #[test]
    fn reap_events_are_emitted_per_pass_and_parse_back() {
        // Each pass tags its removals so any deletion is attributable.
        let cmd = worker_sweep_command("/data/projects", 720, Some(168 * 60), Some(1024));
        assert!(cmd.contains("RCH_REAP_RM %s ttl %s"));
        assert!(cmd.contains("RCH_REAP_RM %s pooled-ttl %s"));
        assert!(cmd.contains("RCH_REAP_RM %s cap %s"));

        let out = "RCH_REAP_RM 2048 ttl /data/projects/r/.rch-target-w-job-1\n\
                   RCH_REAP_RM 512 cap /data/projects/r/.rch-target-w-pool-x\n\
                   RCH_WORKER_REAP_METRICS removed=2 freed_kb=2560\n";
        let events = parse_reap_events(out);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trigger, "ttl");
        assert_eq!(events[1].kb, 512);
        assert_eq!(events[1].trigger, "cap");
        // Untagged bodies (the orchestrator hook path) emit no events.
        let hook_body = reap_loop_body(720, None, "", "");
        assert!(!hook_body.contains("RCH_REAP_RM"));
    }

    #[test]
    fn rm_failures_are_captured_in_tagged_contexts_only() {
        // Tagged sweep bodies capture rm stderr into an ERR event…
        let tagged = reap_loop_body_with_event(720, None, "removed", "freed_kb", Some("ttl"));
        assert!(tagged.contains("RCH_REAP_ERR ttl"));
        assert!(!tagged.contains("rm -rf -- \"$d\" 2>/dev/null"));
        // …while the untagged hook body keeps its historical silent shape.
        let untagged = reap_loop_body(720, None, "removed", "freed_kb");
        assert!(!untagged.contains("RCH_REAP_ERR"));
        assert!(untagged.contains("rm -rf -- \"$d\" 2>/dev/null"));

        // The cap pass captures failures and accounts totals.
        let cmd = worker_sweep_command("/data/projects", 720, None, Some(1024));
        assert!(cmd.contains("RCH_REAP_ERR cap"));
        assert!(cmd.contains("RCH_REAP_CAP initial_kb=%s cap_kb=1024"));
        assert!(cmd.contains("RCH_REAP_CAP final_kb=%s"));
        assert!(cmd.contains("RCH_REAP_SKIP cap %s active %s"));
    }

    #[test]
    fn parse_reap_errors_reads_trigger_path_and_message() {
        let out = "RCH_REAP_RM 5 ttl /data/projects/r/.rch-target-w-job-1\n\
                   RCH_REAP_ERR cap /data/projects/r/.rch-target-w-pool-x :: rm: cannot remove 'x': Permission denied\n\
                   garbage\n";
        let errors = parse_reap_errors(out);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].trigger, "cap");
        assert_eq!(errors[0].path, "/data/projects/r/.rch-target-w-pool-x");
        assert!(errors[0].message.contains("Permission denied"));
    }
}
