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
//! dimensions. The idle-based predicate already keeps them safe — an actively
//! building pool dir has a fresh mtime (cargo writes into it continuously), so
//! it is never evicted while in use — and on top of that they, and the durable
//! `rch-cargo-cache-*` caches, must clear two LIVENESS GATES before anything
//! removes them: no open file descriptor (or cwd) anywhere under the dir, and
//! no live process whose command line names it. See [`gate_snapshot_fragment`]
//! and [`evaluate_gc_candidate`]. A gate that cannot be evaluated counts as
//! "in use": an error must never make a directory eligible for deletion.

/// The glob patterns matched for reaping. Restricted to per-job / per-pid /
/// pooled dirs so a bare `target` (or any non-rch dir) is never touched.
pub const REAP_GLOBS: &[&str] = &[
    ".rch-target-*-job-*",
    ".rch-target-*-pid-*",
    ".rch-target-*-pool-*",
];

/// Basename glob of the DURABLE per-worker Cargo cache dirs
/// (`rch-cargo-cache-<worker>`, issue #42) that `rch gc` enumerates and — under
/// the full gate set — may collect.
///
/// Deliberately NOT in [`REAP_GLOBS`]: that list drives the per-job reaper and
/// the rsync exclude set, where a Cargo cache must never appear. Kept in sync
/// with [`crate::remote_compilation::RCH_CARGO_CACHE_PREFIX`] by
/// `cargo_cache_glob_tracks_the_creating_prefix`.
pub const CARGO_CACHE_GLOB: &str = "rch-cargo-cache-*";

/// Minimum non-zero cargo-cache idle window in minutes (24h), mirroring
/// [`MIN_POOLED_IDLE_MINUTES`]: a durable Cargo cache is a warm cache too, so a
/// misconfigured short window is floored rather than honored.
pub const MIN_CARGO_CACHE_IDLE_MINUTES: u64 = 24 * 60;

/// Convert `[remediation.pooled_target] reaper_pooled_idle_hours` into the
/// pooled idle window in minutes. `0` means "never collect pooled dirs";
/// anything else is floored at [`MIN_POOLED_IDLE_MINUTES`].
///
/// One helper so `rch gc`, `rch cache status`, the daemon sweep and the
/// transfer-start janitor cannot each round the same knob differently.
#[must_use]
pub fn pooled_idle_minutes_from_hours(idle_hours: u32) -> Option<u64> {
    (idle_hours != 0).then(|| (u64::from(idle_hours) * 60).max(MIN_POOLED_IDLE_MINUTES))
}

/// Convert `[remediation.pooled_target] gc_cargo_cache_idle_days` into the
/// cargo-cache idle window in minutes. `0` means "never collect cache dirs";
/// anything else is floored at [`MIN_CARGO_CACHE_IDLE_MINUTES`].
#[must_use]
pub fn cargo_cache_idle_minutes_from_days(idle_days: u32) -> Option<u64> {
    (idle_days != 0).then(|| (u64::from(idle_days) * 24 * 60).max(MIN_CARGO_CACHE_IDLE_MINUTES))
}

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
/// The tmp base is resolved into `$__tmpscan` — canonicalized with `pwd -P`
/// exactly like `$__rt`, and empty when it must not be scanned. Canonicalizing
/// BOTH roots is what makes the string dedup sound: if one root were canonical
/// and the other not, the same physical directory could appear under two
/// spellings and be counted (and byte-capped) twice. The depth guard is applied
/// before AND after resolution, so a `/tmp` fallback that canonicalizes to a
/// deeper path (macOS `/private/tmp`) still does not become sweepable.
/// `$__tmpbase` itself remains the `mktemp` location.
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

/// Shell fragment that builds the two GATE SNAPSHOTS every collection of a
/// pooled/cache dir is required to clear, plus the `__gc_gates_ok` helper that
/// tests one dir against them.
///
/// Two snapshots, taken ONCE per script run (not per candidate — a per-dir
/// `lsof +D` walks the whole tree, and a warm pool holds millions of inodes):
///
/// * `$__held` — every path currently open anywhere on the worker: each
///   process's cwd plus every open file descriptor. Read straight from
///   `/proc/<pid>/{cwd,fd}` with one GNU `find -printf '%l'` (no fork per
///   pid); if `/proc` is unusable it falls back to a single system-wide
///   `lsof -F n`. `$__held_ok` is 1 only when a snapshot was actually
///   produced.
/// * `$__proc` — every process's full command line (`ps -eo args=`), so a
///   build rooted at a dir is caught even when it holds no descriptor open at
///   the instant of the sweep (a `rustc` between writes, a `cargo` driver
///   whose child does the I/O). `$__proc_ok` is 1 only when it is non-empty.
///
/// `__gc_gates_ok <dir>` returns 0 (safe to collect) ONLY when BOTH snapshots
/// exist AND neither matches the dir. Every failure mode — no `/proc`, no
/// `lsof`, no `ps`, an unwritable temp dir — leaves the corresponding `_ok`
/// flag at 0 and the helper returns non-zero, i.e. an unavailable gate makes a
/// dir INELIGIBLE. A false "busy" only wastes disk; a false "free" deletes a
/// live build.
///
/// Matching is exact-prefix via `awk index()`, never a regex: candidate paths
/// come from `find` output and must never be reinterpreted as a pattern.
fn gate_snapshot_fragment() -> String {
    concat!(
        "__held=\"\"; __held_ok=0; __hsrc=none; __proc=\"\"; __proc_ok=0; ",
        "if __held=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null); then ",
        "  if [ -d /proc/self/fd ]; then ",
        "    find /proc/[0-9]*/cwd /proc/[0-9]*/fd -maxdepth 1 -printf '%l\\n' 2>/dev/null > \"$__held\" || :; ",
        "  fi; ",
        "  if [ -s \"$__held\" ]; then __hsrc=proc; ",
        "  elif command -v lsof >/dev/null 2>&1; then ",
        "    lsof -w -n -P -F n 2>/dev/null | sed -n 's/^n//p' > \"$__held\" || :; ",
        "    if [ -s \"$__held\" ]; then __hsrc=lsof; fi; ",
        "  fi; ",
        "  if [ -s \"$__held\" ]; then __held_ok=1; fi; ",
        "fi; ",
        // The sweep's OWN process chain is excluded from the command-line
        // snapshot. `collect_paths_command` embeds the paths it is about to
        // remove into the script, so the shell running it has every one of
        // them in its argv — without this, the gate matches the sweep itself
        // and nothing is ever collected (the `pgrep -f` self-match trap, one
        // level up). Only ancestors are excluded: the snapshot is taken once,
        // before any candidate is examined, so transient children (`awk`,
        // `find`, `du`) that carry a candidate path are not in it.
        "__self_pids=\" $$ \"; __pp=$$; __i=0; ",
        "while [ \"$__i\" -lt 12 ]; do ",
        "  __pp=$(ps -o ppid= -p \"$__pp\" 2>/dev/null | tr -d ' '); ",
        "  case \"$__pp\" in ''|0|1) break;; *[!0-9]*) break;; esac; ",
        "  __self_pids=\"$__self_pids$__pp \"; __i=$((__i + 1)); ",
        "done; ",
        "if __proc=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null); then ",
        "  ps -ww -eo pid=,args= > \"$__proc\" 2>/dev/null ",
        "    || ps -eo pid=,args= > \"$__proc\" 2>/dev/null || :; ",
        "  if [ -s \"$__proc\" ]; then __proc_ok=1; fi; ",
        "fi; ",
        "__gc_handles() { ",
        "  if [ \"$__held_ok\" -ne 1 ]; then printf unknown; return 0; fi; ",
        "  if awk -v p=\"$1\" '$0==p || index($0, p \"/\")==1 {f=1; exit} END{exit(f?0:1)}' \"$__held\"; ",
        "  then printf held; else printf free; fi; ",
        "}; ",
        "__gc_procs() { ",
        "  if [ \"$__proc_ok\" -ne 1 ]; then printf unknown; return 0; fi; ",
        "  if awk -v p=\"$1\" -v skip=\"$__self_pids\" ",
        "    '{ if (index(skip, \" \" $1 \" \") > 0) next; if (index($0, p) > 0) { f=1; exit } } ",
        "     END{exit(f?0:1)}' \"$__proc\"; ",
        "  then printf held; else printf free; fi; ",
        "}; ",
        "__gc_gates_ok() { ",
        "  [ \"$(__gc_handles \"$1\")\" = free ] || return 1; ",
        "  [ \"$(__gc_procs \"$1\")\" = free ] || return 1; ",
        "  return 0; ",
        "}; ",
        "printf 'RCH_GC_GATES handles=%s handles_source=%s procs=%s\\n' \"$__held_ok\" \"$__hsrc\" \"$__proc_ok\"; ",
    )
    .to_string()
}

/// Shell fragment removing the gate-snapshot temp files. Safe when a snapshot
/// was never created (`rm -f ""` is not attempted).
///
/// Written as `if`, NOT as `[ -n "$x" ] && rm -f "$x"`: the `&&` form yields
/// exit status 1 when the variable is empty, and this fragment is the LAST
/// statement of the enumeration script — a worker whose `mktemp` failed would
/// have made the whole read-only enumeration look like a failed command.
fn gate_snapshot_cleanup() -> &'static str {
    "if [ -n \"$__held\" ]; then rm -f \"$__held\"; fi; \
     if [ -n \"$__proc\" ]; then rm -f \"$__proc\"; fi; "
}

/// Gate prefix for a POOLED-dir reap loop body, given that pass's idle window.
///
/// Order matters: the cheap whole-tree `-mmin` idle test runs FIRST and simply
/// `continue`s, so a worker mid-build does not pay two `awk` scans per warm
/// pool, and a worker whose gates are unavailable does not print one skip line
/// per pool it was never going to touch anyway. Only a dir the TTL pass would
/// actually remove is gate-checked, and only that dir's refusal is reported.
fn pooled_collect_gate(idle_minutes: u64) -> String {
    format!(
        "[ -d \"$d\" ] || continue; \
         if find \"$d\" -mmin -{idle_minutes} -print -quit 2>/dev/null | grep -q .; then continue; fi; \
         if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP pooled-ttl gate %s\\n' \"$d\"; continue; fi; "
    )
}

fn candidate_discovery_preamble(escaped_base: &str, on_guard_exit: &str) -> String {
    // The tmp base is resolved by the SAME prelude that creates the durable
    // per-worker Cargo caches and stages target dirs
    // (`remote_cargo_home_base_prelude`), so the sweep cannot look somewhere
    // other than where rch writes. It used to be a hand-copied `$TMPDIR` →
    // `/data/tmp` → `/tmp` ladder here — the duplication that let ~700 GB of
    // pooled/cache dirs sit unscanned while `rch gc` reported 0 MB.
    let tmp_base_prelude = crate::remote_compilation::remote_cargo_home_base_prelude();
    let tmp_base_var = crate::remote_compilation::RCH_CARGO_HOME_BASE_VAR;
    format!(
        "set -u; \
         base=\"{escaped_base}\"; \
         printf 'RCH_GC_ROOT base %s\\n' \"$base\"; \
         if [ ! -d \"$base\" ]; then printf 'RCH_GC_ROOT_SKIPPED %s missing\\n' \"$base\"; {on_guard_exit}exit 0; fi; \
         __rt=$(cd \"$base\" 2>/dev/null && pwd -P) || {{ printf 'RCH_GC_ROOT_SKIPPED %s unresolvable\\n' \"$base\"; {on_guard_exit}exit 0; }}; \
         [ -n \"$__rt\" ] || {{ printf 'RCH_GC_ROOT_SKIPPED %s unresolvable\\n' \"$base\"; {on_guard_exit}exit 0; }}; \
         case \"$__rt\" in */*/*) ;; *) printf 'RCH_GC_ROOT_SKIPPED %s too-shallow\\n' \"$__rt\"; {on_guard_exit}exit 0;; esac; \
         printf 'RCH_GC_ROOT resolved %s\\n' \"$__rt\"; \
         {tmp_base_prelude}; \
         __tmpbase=\"${{{tmp_base_var}}}\"; \
         __tmpscan=\"\"; \
         case \"$__tmpbase\" in /*/*) __tmpscan=$(cd \"$__tmpbase\" 2>/dev/null && pwd -P) || __tmpscan=\"\";; esac; \
         case \"$__tmpscan\" in /*/*) ;; *) __tmpscan=\"\";; esac; \
         printf 'RCH_GC_ROOT tmp %s\\n' \"$__tmpscan\"; \
         {gates}\
         __tmpf=$(mktemp 2>/dev/null || mktemp -p \"$__tmpbase\" 2>/dev/null) || {{ {cleanup}{on_guard_exit}exit 0; }}; \
         find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune 2>/dev/null > \"$__tmpf\"; \
         if [ -n \"$__tmpscan\" ]; then find \"$__tmpscan\" -maxdepth 1 -type d -name \"rch_target_*\" -prune 2>/dev/null >> \"$__tmpf\"; \
           find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune 2>/dev/null >> \"$__tmpf\"; fi; \
         {dedup}",
        gates = gate_snapshot_fragment(),
        cleanup = gate_snapshot_cleanup(),
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
                   if [ -n \"$__tmpscan\" ]; then find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d -name \".rch-target-*-pool-*\" -prune 2>/dev/null >> \"$__tmpf2\"; fi; \
                   {dedup2}\
                   while IFS= read -r d; do {pooled_gate}{pooled_body} done < \"$__tmpf2\"; \
                   rm -f \"$__tmpf2\"; \
                 fi; ",
                pooled_gate = pooled_collect_gate(window),
            )
        }
        None => String::new(),
    };
    // Byte-cap eviction (bead 6dj11): after the TTL passes, when the TOTAL of
    // every remaining reap-class dir exceeds the budget, evict oldest first —
    // but NEVER a dir with activity within the short idle window (the same
    // whole-tree `find -mmin` active-build safety floor as the TTL pass), and
    // never one that fails the liveness gates (a disk budget must not be able
    // to delete a dir a build is holding open) — until back under. Oldest-first makes this a warm-LRU by construction:
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
               if [ -n \"$__tmpscan\" ]; then find \"$__tmpscan\" -maxdepth 1 -type d -name \"rch_target_*\" -prune 2>/dev/null >> \"$__tmpf3\"; \
                 find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" -o -name \".rch-target-*-pool-*\" \\) -prune 2>/dev/null >> \"$__tmpf3\"; fi; \
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
                     printf 'RCH_GC_SKIP cap active %s\\n' \"$d\"; continue; \
                   fi; \
                   if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP cap gate %s\\n' \"$d\"; continue; fi; \
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
         {gate_cleanup}\
         printf 'RCH_WORKER_REAP_METRICS removed=%s freed_kb=%s\\n' \"$removed\" \"$freed_kb\"",
        gate_cleanup = gate_snapshot_cleanup()
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
/// `rch gc`: identical candidate discovery to [`worker_sweep_command`] (so
/// what status shows is exactly what gc would consider), plus the POOLED
/// `.rch-target-*-pool-*` stores and the durable `rch-cargo-cache-*` caches —
/// the two classes that hold most of the bytes on a worker and that gc may
/// collect under the full gate set. Nothing is removed. One line per
/// candidate:
///
/// `RCH_TARGET_ENTRY <newest_mtime_unix> <kb> <handles> <procs> <path>`
///
/// `<handles>` and `<procs>` are the two liveness gates (`free`, `held`, or
/// `unknown`); see [`gate_snapshot_fragment`]. `unknown` is the fail-closed
/// answer and makes a warm-cache dir ineligible.
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
         find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-pool-*\" -o -name \"{cache_glob}\" \\) -prune 2>/dev/null >> \"$__tmpf\"; \
         if [ -n \"$__tmpscan\" ]; then \
           find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-pool-*\" -o -name \"{cache_glob}\" \\) -prune 2>/dev/null >> \"$__tmpf\"; fi; \
         {dedup}\
         while IFS= read -r d; do \
           [ -d \"$d\" ] || continue; \
           set -- $(find \"$d\" -printf '%T@ %s\\n' 2>/dev/null | awk '{{ t=int($1); if (t>n) n=t; s+=$2 }} END {{ printf \"%d %d\", n, int(s/1024) }}'); \
           newest=${{1:-0}}; kb=${{2:-0}}; \
           printf 'RCH_TARGET_ENTRY %s %s %s %s %s\\n' \"$newest\" \"$kb\" \"$(__gc_handles \"$d\")\" \"$(__gc_procs \"$d\")\" \"$d\"; \
         done < \"$__tmpf\"; \
         rm -f \"$__tmpf\"; \
         {gate_cleanup}exit 0",
        cache_glob = CARGO_CACHE_GLOB,
        gate_cleanup = gate_snapshot_cleanup()
    )
}

/// One enumerated remote target dir from [`enumerate_targets_command`] output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTargetEntry {
    /// Newest mtime (Unix seconds) of the dir or any descendant.
    pub newest_mtime_unix: u64,
    /// Disk usage in KiB.
    pub kb: u64,
    /// Absolute path on the worker.
    pub path: String,
    /// Whether any process holds a descriptor open under this dir, or has it
    /// as its cwd. [`GateEvidence::Unknown`] when the snapshot could not be
    /// taken — which makes the dir ineligible, never eligible.
    pub open_handles: GateEvidence,
    /// Whether a live process's command line names this dir.
    /// [`GateEvidence::Unknown`] when the snapshot could not be taken.
    pub live_process: GateEvidence,
}

impl RemoteTargetEntry {
    /// Whether this is a pooled (`-pool-`) dir — a warm cache reused across
    /// jobs.
    #[must_use]
    pub fn is_pooled(&self) -> bool {
        self.class() == GcClass::Pooled
    }

    /// What kind of rch runtime dir this is, from its basename alone.
    #[must_use]
    pub fn class(&self) -> GcClass {
        GcClass::from_path(&self.path)
    }

    /// Idle age in seconds relative to `now_unix`, saturating at 0 for a dir
    /// whose newest mtime is in the future (clock skew between client and
    /// worker) — a future mtime reads as "just touched", i.e. too young.
    #[must_use]
    pub fn age_secs(&self, now_unix: u64) -> u64 {
        now_unix.saturating_sub(self.newest_mtime_unix)
    }
}

/// What kind of rch runtime directory a path names. Derived in Rust from the
/// basename (never in the shell) so classification cannot drift between the
/// enumeration script and the decision that acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GcClass {
    /// `.rch-target-<worker>-job-<id>` / `-pid-<pid>-…`: one build's target dir.
    PerJob,
    /// `.rch-target-<worker>-pool-<key>`: a warm target store shared by jobs.
    Pooled,
    /// `rch-cargo-cache-<worker>`: the durable per-worker `CARGO_HOME`.
    CargoCache,
    /// `rch_target_*`: the pre-`.rch-target-` layout, still found on old hosts.
    LegacyTarget,
    /// Anything else. Never collectible — if the enumeration ever hands back a
    /// path rch does not recognize, gc leaves it alone.
    Unrecognized,
}

impl GcClass {
    /// Classify by basename.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        if let Some(rest) = name.strip_prefix(".rch-target-") {
            if rest.contains("-pool-") {
                return Self::Pooled;
            }
            if rest.contains("-job-") || rest.contains("-pid-") {
                return Self::PerJob;
            }
            return Self::Unrecognized;
        }
        if name.starts_with(crate::remote_compilation::RCH_CARGO_CACHE_PREFIX) {
            return Self::CargoCache;
        }
        if name.starts_with("rch_target_") {
            return Self::LegacyTarget;
        }
        Self::Unrecognized
    }

    /// Stable machine-readable tag (JSON output, tests).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerJob => "per_job",
            Self::Pooled => "pooled",
            Self::CargoCache => "cargo_cache",
            Self::LegacyTarget => "legacy_target",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// The `RCH_REAP_RM` trigger tag recorded for a removal of this class.
    #[must_use]
    pub const fn trigger(self) -> &'static str {
        match self {
            Self::PerJob | Self::LegacyTarget => "ttl",
            Self::Pooled => "pooled-ttl",
            Self::CargoCache => "cache-ttl",
            Self::Unrecognized => "none",
        }
    }

    /// Whether collecting this class demands that BOTH liveness gates be
    /// *known* and free. True for the two warm-cache classes that this change
    /// made collectible: they are shared and long-lived, so an unavailable
    /// gate must block them. Per-job and legacy dirs keep their long-standing
    /// idle-window authority (an unavailable gate does not newly freeze a
    /// sweep that has always been safe on the idle window alone), but a gate
    /// that is available and says "held" still blocks them.
    #[must_use]
    pub const fn requires_known_gates(self) -> bool {
        matches!(self, Self::Pooled | Self::CargoCache)
    }
}

impl std::fmt::Display for GcClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The answer one liveness gate gave for one directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum GateEvidence {
    /// The gate ran and found nothing holding the dir.
    Free,
    /// The gate ran and found the dir in use.
    Held,
    /// The gate could not run (no `/proc`, no `lsof`, no `ps`, unwritable
    /// temp, permission denied). The DEFAULT, so any parse gap or missing
    /// field reads as "unknown" and therefore ineligible.
    #[default]
    Unknown,
}

impl GateEvidence {
    /// Parse the token the enumeration script prints.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "free" => Some(Self::Free),
            "held" => Some(Self::Held),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// The token form.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Held => "held",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for GateEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_token())
    }
}

/// Per-class idle windows, in seconds, that `rch gc` applies. `None` means the
/// class is never collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcPolicy {
    /// Window for [`GcClass::PerJob`] and [`GcClass::LegacyTarget`].
    pub idle_secs: u64,
    /// Window for [`GcClass::Pooled`]; `None` disables pooled collection.
    pub pooled_idle_secs: Option<u64>,
    /// Window for [`GcClass::CargoCache`]; `None` disables cache collection.
    pub cache_idle_secs: Option<u64>,
}

impl GcPolicy {
    /// The idle window a class must clear, or `None` when the class is not
    /// collected at all.
    #[must_use]
    pub fn window_secs(&self, class: GcClass) -> Option<u64> {
        match class {
            GcClass::PerJob | GcClass::LegacyTarget => Some(self.idle_secs),
            GcClass::Pooled => self.pooled_idle_secs,
            GcClass::CargoCache => self.cache_idle_secs,
            GcClass::Unrecognized => None,
        }
    }
}

/// Why a candidate was NOT collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcKeepReason {
    /// The basename is not an rch runtime dir rch is willing to remove.
    Unrecognized,
    /// The class is disabled by configuration (a `0` idle window).
    ClassDisabled,
    /// Not idle long enough yet.
    TooYoung {
        /// Observed idle age.
        age_secs: u64,
        /// Window it must clear.
        required_secs: u64,
    },
    /// A process holds a descriptor open under the dir, or is cwd'd into it.
    OpenHandles,
    /// A live process's command line names the dir.
    LiveProcess,
    /// A gate could not be evaluated. Named so the operator can fix the
    /// worker rather than wonder why nothing is collected.
    GateUnavailable(&'static str),
}

impl std::fmt::Display for GcKeepReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognized => f.write_str("not an rch-managed runtime dir"),
            Self::ClassDisabled => f.write_str("collection disabled for this class by config"),
            Self::TooYoung {
                age_secs,
                required_secs,
            } => write!(
                f,
                "idle {}h < required {}h",
                age_secs / 3600,
                required_secs / 3600
            ),
            Self::OpenHandles => f.write_str("open file descriptors under the dir"),
            Self::LiveProcess => f.write_str("a live process is rooted at the dir"),
            Self::GateUnavailable(gate) => write!(f, "{gate} gate unavailable (treated as in use)"),
        }
    }
}

impl GcKeepReason {
    /// Stable machine-readable tag for JSON output.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unrecognized => "unrecognized",
            Self::ClassDisabled => "class_disabled",
            Self::TooYoung { .. } => "too_young",
            Self::OpenHandles => "open_handles",
            Self::LiveProcess => "live_process",
            Self::GateUnavailable(_) => "gate_unavailable",
        }
    }
}

/// The decision for one enumerated dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcVerdict {
    /// Every gate passed; gc may remove it (`--apply`).
    Collect,
    /// Left in place, with the reason.
    Keep(GcKeepReason),
}

impl GcVerdict {
    /// Whether this dir would be removed.
    #[must_use]
    pub fn is_collect(&self) -> bool {
        matches!(self, Self::Collect)
    }
}

/// Decide whether one enumerated dir may be collected.
///
/// The gates, ALL of which must hold, in the order they are cheapest to
/// explain:
///
/// 1. the basename is a class rch created and is willing to remove;
/// 2. the class is enabled (a `0` window disables it);
/// 3. the dir has been idle at least the class's window — `newest_mtime_unix`
///    is the newest mtime of the dir *or any descendant*, so an active build
///    can never clear this;
/// 4. no open file descriptor and no cwd under the dir;
/// 5. no live process rooted at the dir.
///
/// Any gate that could not be evaluated ([`GateEvidence::Unknown`]) blocks
/// collection for the classes this change newly made collectible — the whole
/// point of the conservative rule is that an error must read as "in use", never
/// as "free".
#[must_use]
pub fn evaluate_gc_candidate(
    entry: &RemoteTargetEntry,
    now_unix: u64,
    policy: &GcPolicy,
) -> GcVerdict {
    let class = entry.class();
    if class == GcClass::Unrecognized {
        return GcVerdict::Keep(GcKeepReason::Unrecognized);
    }
    let Some(required_secs) = policy.window_secs(class) else {
        return GcVerdict::Keep(GcKeepReason::ClassDisabled);
    };
    let age_secs = entry.age_secs(now_unix);
    if age_secs < required_secs {
        return GcVerdict::Keep(GcKeepReason::TooYoung {
            age_secs,
            required_secs,
        });
    }
    let strict = class.requires_known_gates();
    match entry.open_handles {
        GateEvidence::Held => return GcVerdict::Keep(GcKeepReason::OpenHandles),
        GateEvidence::Unknown if strict => {
            return GcVerdict::Keep(GcKeepReason::GateUnavailable("open-descriptor"));
        }
        _ => {}
    }
    match entry.live_process {
        GateEvidence::Held => return GcVerdict::Keep(GcKeepReason::LiveProcess),
        GateEvidence::Unknown if strict => {
            return GcVerdict::Keep(GcKeepReason::GateUnavailable("live-process"));
        }
        _ => {}
    }
    GcVerdict::Collect
}

/// Second-pass byte-cap eviction, in Rust so every eviction carries the same
/// per-dir reasoning as a TTL collection.
///
/// After the TTL verdicts, when the total size of everything still on disk
/// exceeds `cap_kb` (`[remediation.pooled_target] reaper_max_cache_gb`; `0`
/// disables), evict OLDEST-FIRST until back under budget. Returns the indices
/// of `entries` to additionally collect, in eviction order.
///
/// A cap eviction is held to *more* than the TTL pass required of it: the dir
/// must still clear the SHORT idle window (the active-build safety floor — a
/// disk budget must never clip a running build) and must still pass the same
/// liveness gates, including the rule that an unavailable gate blocks a warm
/// cache. The pre-existing shell cap pass checked only the idle window; this
/// is strictly the safer of the two.
#[must_use]
pub fn select_cap_evictions(
    entries: &[RemoteTargetEntry],
    verdicts: &[GcVerdict],
    now_unix: u64,
    policy: &GcPolicy,
    cap_kb: u64,
) -> Vec<usize> {
    if cap_kb == 0 || entries.len() != verdicts.len() {
        return Vec::new();
    }
    let mut remaining_kb: u64 = entries
        .iter()
        .zip(verdicts)
        .filter(|(_, v)| !v.is_collect())
        .map(|(e, _)| e.kb)
        .sum();
    if remaining_kb <= cap_kb {
        return Vec::new();
    }

    let mut candidates: Vec<usize> = entries
        .iter()
        .zip(verdicts)
        .enumerate()
        .filter(|(_, (entry, verdict))| {
            if verdict.is_collect() {
                return false;
            }
            let class = entry.class();
            if class == GcClass::Unrecognized || policy.window_secs(class).is_none() {
                return false;
            }
            if entry.age_secs(now_unix) < policy.idle_secs {
                return false;
            }
            let strict = class.requires_known_gates();
            let gate_ok = |g: GateEvidence| match g {
                GateEvidence::Free => true,
                GateEvidence::Held => false,
                GateEvidence::Unknown => !strict,
            };
            gate_ok(entry.open_handles) && gate_ok(entry.live_process)
        })
        .map(|(idx, _)| idx)
        .collect();
    // Oldest first, so the warm pools that survive are the ones still in use.
    // Path is the tie-break so the order is deterministic across runs.
    candidates.sort_by(|a, b| {
        entries[*a]
            .newest_mtime_unix
            .cmp(&entries[*b].newest_mtime_unix)
            .then_with(|| entries[*a].path.cmp(&entries[*b].path))
    });

    let mut evict = Vec::new();
    for idx in candidates {
        if remaining_kb <= cap_kb {
            break;
        }
        remaining_kb = remaining_kb.saturating_sub(entries[idx].kb);
        evict.push(idx);
    }
    evict
}

/// One dir `rch gc --apply` intends to remove, with the window and tag the
/// worker re-checks it against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcCollectTarget {
    /// Absolute path on the worker.
    pub path: String,
    /// Idle window (minutes) the worker re-verifies before removing.
    pub idle_minutes: u64,
    /// Trigger tag recorded on the removal.
    pub trigger: &'static str,
}

/// Build the removal script for an explicit, already-decided list of dirs.
///
/// This is the ONLY code path by which `rch gc --apply` deletes anything, and
/// it re-runs every gate on the worker immediately before each `rm`:
/// still-a-directory, still idle past its window, no open descriptors, no live
/// process. The client's verdict is therefore a *proposal*; the worker's
/// re-check is the authority, which closes the window between enumeration and
/// removal (a build can start in between — enumeration of a loaded worker takes
/// minutes).
///
/// Every path is re-validated with [`is_safe_reap_path`] and must carry a
/// recognized rch basename, so neither a corrupted enumeration nor a hostile
/// path can widen what gets removed. Returns `Err` naming the offending path
/// rather than silently dropping it.
///
/// Emits the same `RCH_REAP_RM` / `RCH_REAP_ERR` / `RCH_WORKER_REAP_METRICS`
/// lines as [`worker_sweep_command`], plus `RCH_GC_SKIP <trigger> <reason>
/// <path>` for a dir the worker's re-check declined.
pub fn collect_paths_command(targets: &[GcCollectTarget]) -> Result<String, String> {
    if targets.is_empty() {
        return Err("no targets to collect".to_string());
    }
    let mut list = String::new();
    for target in targets {
        if !is_safe_reap_path(&target.path) {
            return Err(format!(
                "refusing to collect {:?}: not an absolute, `..`-free, metacharacter-free path at \
                 least two levels deep",
                target.path
            ));
        }
        if GcClass::from_path(&target.path) == GcClass::Unrecognized {
            return Err(format!(
                "refusing to collect {:?}: basename is not an rch-managed runtime dir",
                target.path
            ));
        }
        if target.idle_minutes == 0 {
            return Err(format!(
                "refusing to collect {:?}: a zero idle window would remove a live dir",
                target.path
            ));
        }
        if !target
            .trigger
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!("invalid trigger tag {:?}", target.trigger));
        }
        list.push_str(&format!(
            " \"{}:{}:{}\"",
            target.idle_minutes, target.trigger, target.path
        ));
    }
    // `$__tmpbase` is the mktemp location for the gate snapshots and is
    // resolved by the very prelude that creates the dirs being collected.
    let tmp_base_prelude = crate::remote_compilation::remote_cargo_home_base_prelude();
    let tmp_base_var = crate::remote_compilation::RCH_CARGO_HOME_BASE_VAR;
    Ok(format!(
        "set -u; \
         {tmp_base_prelude}; \
         __tmpbase=\"${{{tmp_base_var}}}\"; \
         {gates}\
         removed=0; freed_kb=0; \
         for __e in{list}; do \
           __mins=${{__e%%:*}}; __r=${{__e#*:}}; __tag=${{__r%%:*}}; d=${{__r#*:}}; \
           if [ ! -d \"$d\" ]; then printf 'RCH_GC_SKIP %s missing %s\\n' \"$__tag\" \"$d\"; continue; fi; \
           if find \"$d\" -mmin -\"$__mins\" -print -quit 2>/dev/null | grep -q .; then \
             printf 'RCH_GC_SKIP %s active %s\\n' \"$__tag\" \"$d\"; continue; fi; \
           if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP %s gate %s\\n' \"$__tag\" \"$d\"; continue; fi; \
           sz=$(du -sk \"$d\" 2>/dev/null | awk '{{print $1}}'); [ -z \"$sz\" ] && sz=0; \
           if __rmerr=$(rm -rf -- \"$d\" 2>&1); then \
             removed=$((removed + 1)); freed_kb=$((freed_kb + sz)); \
             printf 'RCH_REAP_RM %s %s %s\\n' \"$sz\" \"$__tag\" \"$d\"; \
           else \
             printf 'RCH_REAP_ERR %s %s :: %s\\n' \"$__tag\" \"$d\" \"$(printf '%s' \"$__rmerr\" | head -1)\"; \
           fi; \
         done; \
         {gate_cleanup}\
         printf 'RCH_WORKER_REAP_METRICS removed=%s freed_kb=%s\\n' \"$removed\" \"$freed_kb\"",
        gates = gate_snapshot_fragment(),
        gate_cleanup = gate_snapshot_cleanup(),
    ))
}

/// One dir a `--apply` run declined at removal time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcSkip {
    /// Trigger tag of the pass that declined it.
    pub trigger: String,
    /// Why: `missing`, `active`, or `gate`.
    pub reason: String,
    /// Absolute path.
    pub path: String,
}

/// Parse the `RCH_GC_SKIP <trigger> <reason> <path>` lines.
#[must_use]
pub fn parse_gc_skips(stdout: &str) -> Vec<GcSkip> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("RCH_GC_SKIP ")?;
            let mut parts = rest.splitn(3, ' ');
            let trigger = parts.next()?.to_string();
            let reason = parts.next()?.to_string();
            let path = parts.next()?.trim();
            if path.is_empty() {
                return None;
            }
            Some(GcSkip {
                trigger,
                reason,
                path: path.to_string(),
            })
        })
        .collect()
}

/// The roots one enumeration/sweep run actually looked at, as reported by the
/// script itself (`RCH_GC_ROOT <kind> <path>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanRootReport {
    /// The `$base` handed to the script, verbatim.
    pub requested: Option<String>,
    /// The canonicalized base actually walked, absent when the guard bailed.
    pub resolved: Option<String>,
    /// The canonicalized worker temp base walked, empty/absent when it was
    /// skipped by the shallow-root guard.
    pub temp_base: Option<String>,
    /// `<path> <reason>` for a root the guard refused to walk.
    pub skipped: Option<String>,
}

/// Parse the `RCH_GC_ROOT` / `RCH_GC_ROOT_SKIPPED` lines. Lets `rch gc` report
/// which roots were really scanned instead of the ones it hoped to scan — a
/// root that silently bails is exactly how this bug hid.
#[must_use]
pub fn parse_scan_roots(stdout: &str) -> ScanRootReport {
    let mut report = ScanRootReport::default();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("RCH_GC_ROOT_SKIPPED ") {
            if !rest.is_empty() {
                report.skipped = Some(rest.to_string());
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("RCH_GC_ROOT ") else {
            continue;
        };
        let Some((kind, value)) = rest.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        let slot = match kind {
            "base" => &mut report.requested,
            "resolved" => &mut report.resolved,
            "tmp" => &mut report.temp_base,
            _ => continue,
        };
        *slot = (!value.is_empty()).then(|| value.to_string());
    }
    report
}

/// Whether both liveness-gate snapshots were available on this run, from the
/// `RCH_GC_GATES handles=<0|1> handles_source=<...> procs=<0|1>` line.
///
/// A missing line reads as "unavailable" — the fail-closed direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateAvailability {
    /// Whether the open-descriptor snapshot was taken.
    pub handles: bool,
    /// Whether the process-command-line snapshot was taken.
    pub processes: bool,
}

impl GateAvailability {
    /// Whether both gates could be evaluated.
    #[must_use]
    pub fn both(self) -> bool {
        self.handles && self.processes
    }
}

/// Parse the `RCH_GC_GATES` line.
#[must_use]
pub fn parse_gate_availability(stdout: &str) -> GateAvailability {
    let mut out = GateAvailability::default();
    let Some(line) = stdout.lines().find(|l| l.contains("RCH_GC_GATES")) else {
        return out;
    };
    for token in line.split_whitespace() {
        match token.split_once('=') {
            Some(("handles", v)) => out.handles = v == "1",
            Some(("procs", v)) => out.processes = v == "1",
            _ => {}
        }
    }
    out
}

/// Parse the `RCH_TARGET_ENTRY` lines an [`enumerate_targets_command`] run
/// prints. Unparseable lines are skipped (fail-open observability).
///
/// Two shapes are accepted: the current
/// `<newest> <kb> <handles> <procs> <path>` and the pre-gate
/// `<newest> <kb> <path>`, which parses with both gates
/// [`GateEvidence::Unknown`] — i.e. an old worker script makes every warm-cache
/// dir ineligible rather than eligible-by-omission.
#[must_use]
pub fn parse_target_entries(stdout: &str) -> Vec<RemoteTargetEntry> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("RCH_TARGET_ENTRY ")?;
            let mut parts = rest.splitn(5, ' ');
            let newest_mtime_unix = parts.next()?.parse::<u64>().ok()?;
            let kb = parts.next()?.parse::<u64>().ok()?;
            let third = parts.next()?;
            let (open_handles, live_process, path) = match GateEvidence::from_token(third) {
                Some(handles) => {
                    let live = GateEvidence::from_token(parts.next()?)?;
                    (handles, live, parts.next()?.trim().to_string())
                }
                // Legacy 3-field line: everything after `<kb> ` is the path.
                None => (
                    GateEvidence::Unknown,
                    GateEvidence::Unknown,
                    rest.splitn(3, ' ').nth(2)?.trim().to_string(),
                ),
            };
            if path.is_empty() {
                return None;
            }
            Some(RemoteTargetEntry {
                newest_mtime_unix,
                kb,
                path,
                open_handles,
                live_process,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── gc eligibility model (issue: `rch gc` reported 0 MB fleet-wide) ─────

    fn entry(path: &str, age_secs: u64, gates: (GateEvidence, GateEvidence)) -> RemoteTargetEntry {
        RemoteTargetEntry {
            newest_mtime_unix: NOW - age_secs,
            kb: 4_096,
            path: path.to_string(),
            open_handles: gates.0,
            live_process: gates.1,
        }
    }

    const NOW: u64 = 1_800_000_000;
    const FREE: (GateEvidence, GateEvidence) = (GateEvidence::Free, GateEvidence::Free);
    const DAY: u64 = 24 * 3600;

    fn policy() -> GcPolicy {
        GcPolicy {
            idle_secs: 12 * 3600,
            pooled_idle_secs: Some(7 * DAY),
            cache_idle_secs: Some(14 * DAY),
        }
    }

    const POOL: &str = "/data/projects/repo/.rch-target-hz2-pool-deadbeef";
    const CACHE: &str = "/data/tmp/rch-cargo-cache-hz2";

    /// The glob gc enumerates with must stay welded to the prefix the creator
    /// uses; a rename on one side is exactly how these dirs went unscanned.
    #[test]
    fn cargo_cache_glob_tracks_the_creating_prefix() {
        assert_eq!(
            CARGO_CACHE_GLOB,
            format!("{}*", crate::remote_compilation::RCH_CARGO_CACHE_PREFIX)
        );
        // ...and the durable-cache expression really produces a matching name.
        let expr = crate::remote_compilation::remote_cargo_cache_expr("hz2");
        assert!(expr.ends_with("/rch-cargo-cache-hz2"), "{expr}");
        assert_eq!(
            GcClass::from_path(&expr.replace("${RCH_CH_BASE}", "/data/tmp")),
            GcClass::CargoCache
        );
    }

    #[test]
    fn gc_class_is_derived_from_the_basename() {
        assert_eq!(GcClass::from_path(POOL), GcClass::Pooled);
        assert_eq!(GcClass::from_path(CACHE), GcClass::CargoCache);
        assert_eq!(
            GcClass::from_path("/data/projects/r/.rch-target-hz2-job-1-2-0"),
            GcClass::PerJob
        );
        assert_eq!(
            GcClass::from_path("/data/projects/r/.rch-target-hz2-pid-42-1-0"),
            GcClass::PerJob
        );
        assert_eq!(
            GcClass::from_path("/data/tmp/rch_target_old"),
            GcClass::LegacyTarget
        );
        // Never anything else: a bare target dir, a source tree, a git dir.
        for other in [
            "/data/projects/repo/target",
            "/data/projects/repo",
            "/data/projects/repo/.git",
            "/data/projects/repo/.rch-target-hz2",
            "/data/tmp/rch-cargo-home-hz2-run-7",
        ] {
            assert_eq!(
                GcClass::from_path(other),
                GcClass::Unrecognized,
                "{other} must never be collectible"
            );
        }
    }

    /// The behaviour the fix exists for: an old, quiet pooled dir IS eligible.
    #[test]
    fn pool_and_cache_dirs_are_eligible_when_every_gate_passes() {
        for (path, age) in [(POOL, 8 * DAY), (CACHE, 15 * DAY)] {
            assert_eq!(
                evaluate_gc_candidate(&entry(path, age, FREE), NOW, &policy()),
                GcVerdict::Collect,
                "{path} should be collectible"
            );
        }
    }

    /// Each gate ALONE must be able to veto a collection.
    #[test]
    fn every_gate_independently_blocks_collection() {
        let p = policy();

        // 1. age
        assert_eq!(
            evaluate_gc_candidate(&entry(POOL, 6 * DAY, FREE), NOW, &p),
            GcVerdict::Keep(GcKeepReason::TooYoung {
                age_secs: 6 * DAY,
                required_secs: 7 * DAY
            })
        );
        assert_eq!(
            evaluate_gc_candidate(&entry(CACHE, 13 * DAY, FREE), NOW, &p),
            GcVerdict::Keep(GcKeepReason::TooYoung {
                age_secs: 13 * DAY,
                required_secs: 14 * DAY
            })
        );

        // 2. open file descriptors
        assert_eq!(
            evaluate_gc_candidate(
                &entry(POOL, 99 * DAY, (GateEvidence::Held, GateEvidence::Free)),
                NOW,
                &p
            ),
            GcVerdict::Keep(GcKeepReason::OpenHandles)
        );

        // 3. a live build process rooted at the dir
        assert_eq!(
            evaluate_gc_candidate(
                &entry(POOL, 99 * DAY, (GateEvidence::Free, GateEvidence::Held)),
                NOW,
                &p
            ),
            GcVerdict::Keep(GcKeepReason::LiveProcess)
        );

        // 4. class disabled by configuration
        let disabled = GcPolicy {
            pooled_idle_secs: None,
            cache_idle_secs: None,
            ..p
        };
        for path in [POOL, CACHE] {
            assert_eq!(
                evaluate_gc_candidate(&entry(path, 99 * DAY, FREE), NOW, &disabled),
                GcVerdict::Keep(GcKeepReason::ClassDisabled)
            );
        }

        // 5. an unrecognized dir is never collected, at any age.
        assert_eq!(
            evaluate_gc_candidate(
                &entry("/data/projects/repo/target", 99 * DAY, FREE),
                NOW,
                &p
            ),
            GcVerdict::Keep(GcKeepReason::Unrecognized)
        );
    }

    /// The conservative rule: a gate that ERRORED reads as "in use". A dir that
    /// fails to prove itself free is never collected.
    #[test]
    fn an_unavailable_gate_makes_a_warm_cache_dir_ineligible() {
        let p = policy();
        for gates in [
            (GateEvidence::Unknown, GateEvidence::Free),
            (GateEvidence::Free, GateEvidence::Unknown),
            (GateEvidence::Unknown, GateEvidence::Unknown),
        ] {
            for path in [POOL, CACHE] {
                let verdict = evaluate_gc_candidate(&entry(path, 99 * DAY, gates), NOW, &p);
                assert!(
                    matches!(verdict, GcVerdict::Keep(GcKeepReason::GateUnavailable(_))),
                    "{path} with gates {gates:?} must be ineligible, got {verdict:?}"
                );
            }
        }
    }

    /// Per-job dirs keep the idle window as their authority (an unavailable
    /// gate must not newly freeze a sweep that has always been safe on age
    /// alone) — but a gate that DID run and says "held" still vetoes them.
    #[test]
    fn per_job_dirs_keep_idle_window_authority_but_still_honour_a_live_gate() {
        let p = policy();
        let job = "/data/projects/repo/.rch-target-hz2-job-1-2-0";
        assert_eq!(
            evaluate_gc_candidate(
                &entry(job, 2 * DAY, (GateEvidence::Unknown, GateEvidence::Unknown)),
                NOW,
                &p
            ),
            GcVerdict::Collect
        );
        assert_eq!(
            evaluate_gc_candidate(
                &entry(job, 2 * DAY, (GateEvidence::Held, GateEvidence::Unknown)),
                NOW,
                &p
            ),
            GcVerdict::Keep(GcKeepReason::OpenHandles)
        );
    }

    /// A worker mtime AHEAD of the client's clock must read as "just touched",
    /// never as a huge age that would collect a live dir.
    #[test]
    fn a_future_mtime_reads_as_zero_age() {
        let mut e = entry(POOL, 0, FREE);
        e.newest_mtime_unix = NOW + 10_000;
        assert_eq!(e.age_secs(NOW), 0);
        assert!(matches!(
            evaluate_gc_candidate(&e, NOW, &policy()),
            GcVerdict::Keep(GcKeepReason::TooYoung { .. })
        ));
    }

    #[test]
    fn idle_window_helpers_floor_and_disable() {
        assert_eq!(pooled_idle_minutes_from_hours(0), None);
        assert_eq!(
            pooled_idle_minutes_from_hours(1),
            Some(MIN_POOLED_IDLE_MINUTES)
        );
        assert_eq!(pooled_idle_minutes_from_hours(168), Some(168 * 60));
        assert_eq!(cargo_cache_idle_minutes_from_days(0), None);
        assert_eq!(
            cargo_cache_idle_minutes_from_days(1),
            Some(MIN_CARGO_CACHE_IDLE_MINUTES)
        );
        assert_eq!(cargo_cache_idle_minutes_from_days(14), Some(14 * 24 * 60));
    }

    /// An old worker script (or a truncated line) yields UNKNOWN gates, which
    /// is the ineligible direction — never eligible-by-omission.
    #[test]
    fn legacy_entry_lines_parse_with_unknown_gates_and_are_ineligible() {
        let legacy = format!("RCH_TARGET_ENTRY {} 4096 {POOL}\n", NOW - 99 * DAY);
        let entries = parse_target_entries(&legacy);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, POOL);
        assert_eq!(entries[0].open_handles, GateEvidence::Unknown);
        assert_eq!(entries[0].live_process, GateEvidence::Unknown);
        assert!(matches!(
            evaluate_gc_candidate(&entries[0], NOW, &policy()),
            GcVerdict::Keep(GcKeepReason::GateUnavailable(_))
        ));

        let current = format!(
            "RCH_TARGET_ENTRY {} 4096 free free {POOL}\n",
            NOW - 99 * DAY
        );
        let entries = parse_target_entries(&current);
        assert_eq!(entries[0].path, POOL);
        assert_eq!(entries[0].open_handles, GateEvidence::Free);
        assert_eq!(
            evaluate_gc_candidate(&entries[0], NOW, &policy()),
            GcVerdict::Collect
        );
    }

    #[test]
    fn gate_availability_defaults_to_unavailable() {
        assert_eq!(
            parse_gate_availability("nothing here"),
            GateAvailability::default()
        );
        assert!(!parse_gate_availability("").both());
        let ok = parse_gate_availability("RCH_GC_GATES handles=1 handles_source=proc procs=1\n");
        assert!(ok.both());
        let partial =
            parse_gate_availability("RCH_GC_GATES handles=1 handles_source=proc procs=0\n");
        assert!(!partial.both());
        assert!(partial.handles);
    }

    #[test]
    fn scan_roots_and_skips_are_reported_back() {
        let out = "RCH_GC_ROOT base /srv\nRCH_GC_ROOT_SKIPPED /srv too-shallow\n";
        let roots = parse_scan_roots(out);
        assert_eq!(roots.requested.as_deref(), Some("/srv"));
        assert_eq!(roots.resolved, None);
        assert_eq!(roots.skipped.as_deref(), Some("/srv too-shallow"));

        let out = "RCH_GC_ROOT base /data/projects\nRCH_GC_ROOT resolved /data/projects\nRCH_GC_ROOT tmp \n";
        let roots = parse_scan_roots(out);
        assert_eq!(roots.resolved.as_deref(), Some("/data/projects"));
        assert_eq!(
            roots.temp_base, None,
            "an unscanned tmp base is absent, not empty-string"
        );
        assert_eq!(roots.skipped, None);
    }

    #[test]
    fn collect_paths_command_refuses_anything_it_did_not_recognize() {
        let good = GcCollectTarget {
            path: POOL.to_string(),
            idle_minutes: 10_080,
            trigger: "pooled-ttl",
        };
        assert!(collect_paths_command(std::slice::from_ref(&good)).is_ok());
        assert!(collect_paths_command(&[]).is_err());

        for bad_path in [
            "/",
            "/tmp",
            "relative/.rch-target-w-pool-a",
            "/tmp/../etc/.rch-target-w-pool-a",
            "/tmp/x/.rch-target-w-pool-a; rm -rf /",
            "/data/projects/repo/target",
            "/data/projects/repo",
        ] {
            let t = GcCollectTarget {
                path: bad_path.to_string(),
                ..good.clone()
            };
            assert!(
                collect_paths_command(&[t]).is_err(),
                "{bad_path} must be refused"
            );
        }

        // A zero window would remove a dir that is being written to right now.
        let zero = GcCollectTarget {
            idle_minutes: 0,
            ..good.clone()
        };
        assert!(collect_paths_command(&[zero]).is_err());
    }

    #[test]
    fn collect_paths_command_rechecks_every_gate_on_the_worker() {
        let cmd = collect_paths_command(&[GcCollectTarget {
            path: POOL.to_string(),
            idle_minutes: 10_080,
            trigger: "pooled-ttl",
        }])
        .expect("valid target");

        // Still a directory, still idle, still unheld — checked in that order,
        // immediately before the rm, so the enumerate→apply window is closed.
        assert!(cmd.contains("if [ ! -d \"$d\" ]; then printf 'RCH_GC_SKIP %s missing"));
        assert!(cmd.contains("find \"$d\" -mmin -\"$__mins\" -print -quit"));
        assert!(cmd.contains("if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP %s gate"));
        assert!(cmd.contains("rm -rf -- \"$d\""));
        assert!(cmd.contains("RCH_WORKER_REAP_METRICS"));
        // The gate snapshots exist, and an unavailable one fails closed.
        assert!(cmd.contains("__gc_gates_ok() {"));
        assert!(cmd.contains("[ \"$(__gc_handles \"$1\")\" = free ] || return 1"));
        assert!(cmd.contains("[ \"$(__gc_procs \"$1\")\" = free ] || return 1"));
        assert!(cmd.contains("__held_ok\" -ne 1 ]; then printf unknown"));
        assert!(cmd.contains("__proc_ok\" -ne 1 ]; then printf unknown"));
    }

    /// The gates must ride on the SAME temp-base resolution that creates the
    /// dirs, not a second copy of the ladder.
    #[test]
    fn scan_roots_reuse_the_creating_prelude() {
        let prelude = crate::remote_compilation::remote_cargo_home_base_prelude();
        for cmd in [
            enumerate_targets_command("/data/projects"),
            worker_sweep_command("/data/projects", 720, Some(10_080), None),
            collect_paths_command(&[GcCollectTarget {
                path: POOL.to_string(),
                idle_minutes: 10_080,
                trigger: "pooled-ttl",
            }])
            .unwrap(),
        ] {
            assert!(
                cmd.contains(&prelude),
                "the temp base must come from remote_cargo_home_base_prelude, not a copy"
            );
        }
        // ...and the old hand-copied ladder is gone for good.
        let cmd = enumerate_targets_command("/data/projects");
        assert!(!cmd.contains("__tmpbase=\"${TMPDIR:-}\""));
    }

    /// The enumeration is read-only and its exit status must mean "the SSH
    /// command ran", nothing else. A `[ -n "$x" ] && rm -f "$x"` tail would
    /// exit 1 on a worker whose `mktemp` failed and turn a healthy read-only
    /// scan into a reported worker failure.
    #[test]
    fn enumeration_cannot_exit_nonzero_because_a_temp_file_was_never_made() {
        let cmd = enumerate_targets_command("/data/projects");
        assert!(
            cmd.trim_end().ends_with("exit 0"),
            "enumerate must end with an explicit status"
        );
        for var in ["__held", "__proc"] {
            assert!(
                !cmd.contains(&format!("[ -n \"${var}\" ] && rm -f")),
                "${var} cleanup must be an `if`, not an `&&` whose failure becomes the exit status"
            );
            assert!(cmd.contains(&format!("if [ -n \"${var}\" ]; then rm -f \"${var}\"; fi")));
        }
    }

    /// The gates are consulted only for a dir the TTL pass would actually
    /// remove: the cheap idle test runs first, so a busy worker does not pay
    /// two `awk` scans per warm pool nor emit a skip line for every one.
    #[test]
    fn pooled_gate_runs_after_the_cheap_idle_test() {
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), None);
        let gate = cmd
            .find("__gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP pooled-ttl")
            .expect("pooled gate present");
        let idle = cmd
            .find("find \"$d\" -mmin -10080 -print -quit")
            .expect("pooled idle test present");
        assert!(idle < gate, "the idle test must precede the gate check");
    }

    #[test]
    fn byte_cap_eviction_is_gated_on_liveness_too() {
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), Some(1024));
        assert!(
            cmd.contains("if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP cap gate"),
            "a disk budget must not evict a dir a build is holding open"
        );
        assert!(cmd.contains("printf 'RCH_GC_SKIP cap active"));
    }

    #[test]
    fn pooled_sweep_pass_is_gated_on_liveness() {
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), None);
        assert!(
            cmd.contains("if ! __gc_gates_ok \"$d\"; then printf 'RCH_GC_SKIP pooled-ttl gate"),
            "the daemon sweep must apply the same liveness gates to pooled dirs"
        );
        // The daemon sweep must NOT delete durable Cargo caches: that class is
        // collected only by an explicit, dry-run-by-default `rch gc --apply`.
        assert!(!cmd.contains("rch-cargo-cache-*"));
    }

    #[test]
    fn byte_cap_evicts_oldest_first_and_only_past_the_active_floor() {
        let p = policy();
        // Three pools, all within their 7-day pooled TTL so none is collected
        // by the TTL pass; two are past the SHORT (12h) active-build floor.
        let mut entries = vec![
            entry(POOL, 5 * DAY, FREE), // oldest
            entry("/data/projects/r/.rch-target-hz2-pool-b", 2 * DAY, FREE),
            entry("/data/projects/r/.rch-target-hz2-pool-c", 60, FREE), // fresh
        ];
        for e in &mut entries {
            e.kb = 10_000;
        }
        let verdicts: Vec<GcVerdict> = entries
            .iter()
            .map(|e| evaluate_gc_candidate(e, NOW, &p))
            .collect();
        assert!(verdicts.iter().all(|v| !v.is_collect()));

        // No cap configured: nothing extra.
        assert!(select_cap_evictions(&entries, &verdicts, NOW, &p, 0).is_empty());
        // Under budget: nothing extra.
        assert!(select_cap_evictions(&entries, &verdicts, NOW, &p, 30_000).is_empty());
        // 30_000 KB on disk, 15_000 budget: evict the oldest until under.
        let evicted = select_cap_evictions(&entries, &verdicts, NOW, &p, 15_000);
        assert_eq!(evicted, vec![0, 1]);
        // The fresh dir is never evicted, however tight the budget.
        let evicted = select_cap_evictions(&entries, &verdicts, NOW, &p, 1);
        assert_eq!(
            evicted,
            vec![0, 1],
            "the active-build floor outranks the cap"
        );
    }

    #[test]
    fn byte_cap_still_honours_the_liveness_gates() {
        let p = policy();
        let mut held = entry(POOL, 5 * DAY, (GateEvidence::Held, GateEvidence::Free));
        held.kb = 10_000;
        let mut unknown = entry(
            "/data/projects/r/.rch-target-hz2-pool-b",
            5 * DAY,
            (GateEvidence::Unknown, GateEvidence::Unknown),
        );
        unknown.kb = 10_000;
        let entries = vec![held, unknown];
        let verdicts: Vec<GcVerdict> = entries
            .iter()
            .map(|e| evaluate_gc_candidate(e, NOW, &p))
            .collect();
        assert!(
            select_cap_evictions(&entries, &verdicts, NOW, &p, 1).is_empty(),
            "a held dir and an unprovable dir must both survive the cap"
        );
    }

    #[test]
    fn gc_skip_lines_parse_back() {
        let out = "RCH_GC_SKIP pooled-ttl gate /a/b/.rch-target-w-pool-x\n\
                   RCH_GC_SKIP cache-ttl active /a/b/rch-cargo-cache-w\n\
                   RCH_GC_SKIP bogus\n";
        let skips = parse_gc_skips(out);
        assert_eq!(skips.len(), 2);
        assert_eq!(skips[0].trigger, "pooled-ttl");
        assert_eq!(skips[0].reason, "gate");
        assert_eq!(skips[1].path, "/a/b/rch-cargo-cache-w");
    }

    /// End-to-end on a real fixture: an aged pooled dir and an aged Cargo cache
    /// are BOTH enumerated, both report free gates, and a dir this very test
    /// process holds a descriptor into reports `held` and survives `--apply`.
    ///
    /// Linux-only: the descriptor snapshot reads `/proc/<pid>/fd`, and the
    /// `lsof` fallback would scan every open file on the host — fine on a
    /// worker, not something to make a unit test wait for on a dev Mac.
    #[cfg(target_os = "linux")]
    #[test]
    fn open_descriptors_keep_a_stale_pool_alive_end_to_end() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("projects");
        let tmpbase = tmp.path().join("scratch");
        let free_pool = base.join("repo").join(".rch-target-w1-pool-free");
        let held_pool = base.join("repo").join(".rch-target-w1-pool-held");
        let cache = tmpbase.join("rch-cargo-cache-w1");
        for d in [&free_pool, &held_pool, &cache] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("artifact.o"), b"xxxx").unwrap();
        }
        for d in [&free_pool, &held_pool, &cache] {
            let ok = Command::new("find")
                .arg(d)
                .args(["-exec", "touch", "-t", "202001010000", "{}", "+"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return; // no usable find/touch here
            }
        }

        // Hold a descriptor open under one pool for the rest of the test.
        let _guard = std::fs::File::open(held_pool.join("artifact.o")).unwrap();

        let enumerate = enumerate_targets_command(base.to_str().unwrap());
        let out = Command::new("sh")
            .arg("-c")
            .arg(&enumerate)
            .env("TMPDIR", &tmpbase)
            .output()
            .expect("enumerate should execute");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            parse_gate_availability(&stdout).both(),
            "both gate snapshots must be available on Linux: {stdout}"
        );
        let entries = parse_target_entries(&stdout);
        let find = |needle: &str| {
            entries
                .iter()
                .find(|e| e.path.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not enumerated in {entries:?}"))
        };
        assert_eq!(find("rch-cargo-cache-w1").class(), GcClass::CargoCache);
        assert_eq!(find("pool-held").open_handles, GateEvidence::Held);
        assert_eq!(find("pool-free").open_handles, GateEvidence::Free);

        // `--apply` must remove the free pool and the cache, and refuse the
        // held one even though it is just as old.
        let targets: Vec<GcCollectTarget> = [&free_pool, &held_pool, &cache]
            .iter()
            .map(|d| GcCollectTarget {
                path: std::fs::canonicalize(d)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                idle_minutes: MIN_POOLED_IDLE_MINUTES,
                trigger: "pooled-ttl",
            })
            .collect();
        let cmd = collect_paths_command(&targets).expect("targets are valid");
        let out = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("TMPDIR", &tmpbase)
            .output()
            .expect("collect should execute");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "collect must be valid sh: {stderr}");
        assert!(
            !stderr.contains("syntax error") && !stderr.contains("unexpected"),
            "collect emitted shell errors: {stderr}"
        );
        assert!(
            !free_pool.exists(),
            "an idle, unheld pool must be collected"
        );
        assert!(
            !cache.exists(),
            "an idle, unheld cargo cache must be collected"
        );
        assert!(
            held_pool.exists(),
            "a pool with an open descriptor must survive: {stdout}"
        );
        let skipped = parse_gc_skips(&stdout);
        assert!(
            skipped
                .iter()
                .any(|s| s.path.contains("pool-held") && s.reason == "gate"),
            "the held pool must be reported as gate-skipped: {stdout}"
        );
        assert_eq!(parse_worker_reap_metrics(&stdout).map(|m| m.0), Some(2));
    }

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
            "find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\)"
        )));
        // Pooled pass reaches the tmp base too.
        assert!(cmd.contains(&format!(
            "find \"$__tmpscan\" -maxdepth {TMPBASE_MAXDEPTH} -type d -name \".rch-target-*-pool-*\""
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
        let cmd = worker_sweep_command("/data/projects", 720, Some(10_080), Some(1024));

        // The depth guard is applied to the raw tmp base before resolution AND
        // to the resolved path, so neither a shallow `/tmp` nor a `/tmp` that
        // canonicalizes deeper (macOS `/private/tmp`) becomes sweepable.
        assert!(cmd.contains("case \"$__tmpbase\" in /*/*) __tmpscan="));
        assert!(cmd.contains("case \"$__tmpscan\" in /*/*) ;; *) __tmpscan=\"\";; esac"));
        // Both roots are canonicalized, which is what makes string dedup sound.
        assert!(cmd.contains("__rt=$(cd \"$base\" 2>/dev/null && pwd -P)"));
        assert!(cmd.contains("__tmpscan=$(cd \"$__tmpbase\" 2>/dev/null && pwd -P)"));

        // Every tmp-base scan must sit behind the resolved, guarded variable —
        // never scan `$__tmpbase` directly, which is only the mktemp location.
        assert!(
            !cmd.contains("find \"$__tmpbase\""),
            "tmp-base scans must use the resolved $__tmpscan, not $__tmpbase"
        );
        // ...and each such scan is gated on it being non-empty.
        let scans = cmd.matches("find \"$__tmpscan\"").count();
        let gates = cmd.matches("if [ -n \"$__tmpscan\" ]; then").count();
        assert!(
            scans >= 4,
            "expected the job/pid, legacy, pooled and cap scans"
        );
        assert!(
            gates >= 3,
            "every tmp-base scan group must be gated on $__tmpscan being set"
        );
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
            "if [ -n \"$__tmpscan\" ]; then find \"$__tmpscan\" -maxdepth 1 -type d -name \"rch_target_*\" -prune"
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
        // Pooled dirs AND the durable per-worker Cargo caches, in one pass.
        assert!(cmd.contains(
            "\\( -name \".rch-target-*-pool-*\" -o -name \"rch-cargo-cache-*\" \\) -prune"
        ));
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

        let cmd = worker_sweep_command(
            base.to_str().unwrap(),
            60,
            Some(MIN_POOLED_IDLE_MINUTES),
            None,
        );
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
        assert!(
            !stale_job.exists(),
            "stale job dir under $base must be reaped"
        );
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
        let entries = parse_target_entries(&stdout);
        let listed: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

        // Both roots are canonicalized by the script (`pwd -P`), so compare
        // canonical paths — on macOS a tempdir under /var resolves to
        // /private/var and a literal comparison would spuriously fail.
        for expected in [&tmp_pool, &base_pool, &tmp_job] {
            let want = std::fs::canonicalize(expected).unwrap_or_else(|_| expected.clone());
            let matched = listed.iter().any(|p| {
                std::fs::canonicalize(p).map(|c| c == want).unwrap_or(false)
                    || std::path::Path::new(p) == want
            });
            assert!(
                matched,
                "enumerate must list {}; listed: {listed:?}",
                want.display()
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

        let cmd = worker_sweep_command(
            base.to_str().unwrap(),
            60,
            Some(MIN_POOLED_IDLE_MINUTES),
            None,
        );
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
        // Cap skips now speak the parseable `RCH_GC_SKIP <trigger> <reason>
        // <path>` shape the gc surfaces read back, and carry the gate reason.
        assert!(cmd.contains("RCH_GC_SKIP cap active %s"));
        assert!(cmd.contains("RCH_GC_SKIP cap gate %s"));
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
