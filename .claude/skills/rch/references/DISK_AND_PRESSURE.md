# Worker Disk & Resource Pressure

## Contents

- [Where Worker Disk Actually Goes](#where-worker-disk-actually-goes)
- [Pressure Surfaces RCH Tracks](#pressure-surfaces-rch-tracks)
- [The First Mistake: Filesystem Confusion](#the-first-mistake-filesystem-confusion)
- [Reap With `rch`, Not `rm`](#reap-with-rch-not-rm)
- [Automatic Hygiene (what runs without you)](#automatic-hygiene-what-runs-without-you)
- [Inspect First, Delete Second](#inspect-first-delete-second)
- [Hand Off to `sbh`](#hand-off-to-sbh)
- [When `sbh` Doesn't Help (RCH-E215 / E216 / E217)](#when-sbh-doesnt-help-rch-e215--e216--e217)
- [Memory (E214), I/O (E213), Telemetry (E212)](#memory-e214-io-e213-telemetry-e212)
- [Preventive Hygiene](#preventive-hygiene)
- [Triage Cheat Sheet](#triage-cheat-sheet)

Disk pressure on workers is the single biggest source of "rch was working, now
it isn't". This file is the canonical playbook and the handoff protocol to the
`sbh` skill.

## Where Worker Disk Actually Goes

| Location on the worker | What | Managed by |
|---|---|---|
| `<canonical root>/<repo>/.rch-target-<worker>-pool-<key>` | **pooled** remote target dirs (default shape; reused across jobs for warm incremental builds) | reaper: pooled pass, idle > 168 h |
| `<repo>/.rch-target-*-job-*`, `.rch-target-*-pid-*` | legacy per-job target dirs (`RCH_DISABLE_TARGET_REUSE=1`) | reaper: idle > 12 h |
| `$TMPDIR` / `/data/tmp` / `/tmp` (depth ≤ 6) | pooled/per-job dirs that landed under the tmp base — before the tmp-base pass these grew to 110–129 GB per worker while `rch gc` truthfully reported "removed 0" | reaper (tmp-base pass) |
| `<repo>/.rch-tmp/` | per-job scratch (`TMPDIR` rewrite); `rch-cargo-cache-*` = durable per-worker `CARGO_HOME` | transfer-start janitor: > 24 h scratch, > 3 d caches |
| `<repo>/.rch-go/{cache,mod,path}` | Go caches (`GOCACHE`/`GOMODCACHE`/`GOPATH` rewrite) | janitor |
| `/data/tmp/rch/<project>/<nonce>` (`transfer.remote_base`) | clean-overlay staging roots | reaped at teardown (bead `bd-p1vlb`, soak open); `rch cache clean --base` |
| `~/.cache/rch/rabs-state/cas` | RABS content-addressed store | `rch rabs gc` (opt-in subsystem) |
| `/tmp/rch_target_*` | **pre-pooled-era** name; only on workers never cleaned since | legacy depth-1 pass in `rch gc` (`target_rch_*`/`target_*` trees are *not* rch-managed — manual only) |

A bare `target/`, sources, `.git`, `.beads` are never touched by any rch reaper.

## Pressure Surfaces RCH Tracks

| Code | Meaning | Severity |
|---|---|---|
| `RCH-E210` | disk critically high | critical — selection skips the worker (`RCH-I002`) |
| `RCH-E211` | disk above warning threshold | warning — biases selection away |
| `RCH-E212` | pressure telemetry stale/missing (`RCH-I008`) | warning |
| `RCH-E213` / `E214` | I/O util / memory pressure high | warning, transient |
| `RCH-E215` | reclaim failed | critical |
| `RCH-E216` | insufficient headroom for build reservation | critical |
| `RCH-E217` | active-build protection prevented reclaim | informational |

Thresholds (`[remediation.disk_pressure]`): warning at 15 % free, critical at
5 % free, inode warning 100k / critical 10k; auto-rejoin needs ≥ 5 GB free.

Since `2c69f29` the worker probe reports the **worst-case** free space across
project roots *and* `/tmp` (a 100 %-full tmpfs `/tmp` used to score green while
`/` was healthy).

Where they show:

- `rch --json status --workers` → `.data.daemon.workers[]` flat fields:
  `pressure_state`, `pressure_reason_code`, `pressure_confidence`,
  `pressure_disk_free_gb`, `pressure_disk_total_gb`, `pressure_disk_free_ratio`,
  `pressure_disk_io_util_pct`, `pressure_memory_pressure`,
  `pressure_telemetry_age_secs`, `pressure_telemetry_fresh`, `pressure_policy_rule`
- `rch status --remediation` → "Disk Pressure … N worker(s) at critical … tightest free-disk ratio"
- `rch doctor --reliability --scope pressure` → `RCH-R100..R105`; runbook `RCH-R101`
- `[RCH] remote <worker> failed [RCH-E2xx]` summary line

## The First Mistake: Filesystem Confusion

Mirrors live under the canonical root (`/data/projects`, often on `/` or
`/data`); staging under `transfer.remote_base` (`/data/tmp/rch` by default —
older docs said `/tmp/rch`); scratch under `$TMPDIR`. Check all of them before
deciding what to fix:

```bash
ssh <user>@<host> 'df -h / /data /tmp 2>/dev/null; free -h; cat /proc/pressure/memory /proc/pressure/io'
```

- `/tmp` (or `/data/tmp`) hot, `/` fine → staging / tmp-base target dirs → `rch gc`
- `/` hot → pooled `.rch-target-*` trees under the mirrors → `rch cache status`, `rch gc`
- both hot → `sbh` reclaim, then targeted cleanup

## Reap With `rch`, Not `rm`

```bash
rch cache status --workers <id>            # read-only: every .rch-target-* dir with size, idle age, verdict
rch gc --dry-run --workers <id>            # what the daemon's sweep WOULD remove (does not simulate the byte cap)
rch gc --workers <id>                      # 1.0.58: remove now; emits RCH_REAP_RM <kb> <ttl|pooled-ttl|cap> <path> per dir
rch gc --apply --workers <id>              # 2.0.0: bare `rch gc` only previews; --apply removes
rch cache clean --older 24h --execute      # local + configured staging bases (dry-run without --execute)
rch cache clean --base /tmp/rch-sync --execute   # extra/drifted staging bases
```

Verdicts: `REAPABLE` (idle past window, nothing modified in the tree) ·
`pooled (kept)` (pooled dir inside its 7-day window) · `active/recent (kept)`.
A directory is reaped only if neither it nor any descendant was modified within
the window; live builds touch continuously, so they cannot be clipped.

Known bug on 1.0.58 (`bd-rch-gc-all-workers-hang-wm7ep`, P1): `rch gc` with **no
`--workers`** can hang sweeping all workers (no per-worker timeout). Pass
`--workers <id>` explicitly. Fixed in 2.0.0, which bounds each worker with
`--worker-timeout` (default 900 s) and reports partial results.

`rch rabs gc` is a different thing (RABS CAS) — not for target-dir pressure.

## Automatic Hygiene (what runs without you)

- **Transfer-start janitor** (every `rch exec`, folded into the rsync path):
  prunes `<repo>/.rch-tmp/*` > 24 h, `rch-cargo-cache-*` > 3 days, and
  `.rch-target-*-pool-*` > 3 days — all under the *dispatched project only*.
  Non-fatal. Note the two pooled windows: the janitor's 3-day rule fires for
  the project you are building right now, while the fleet-wide reaper /
  `rch gc` keeps pooled dirs for 168 h; a pool idle 4–7 days therefore shows
  as `pooled (kept)` in `rch cache status` yet is removed the next time *that
  project* is dispatched to that worker.
- **Daemon periodic reaper**: ships **OFF** (`[stale_target_reap] enabled =
  false` / `[remediation.pooled_target] reaper_enabled = false`) — "an
  autonomous periodic deleter pointed at /data/projects, the exact class of
  mechanism behind a prior fleet-wide carnage incident". Enable with
  `RCH_WORKER_REAP_ENABLE=1` on the daemon (interval 120 min, idle 12 h, pooled
  168 h, optional byte-cap LRU `max_cache_gb`). `RCH_WORKER_REAP_DISABLE` always
  wins.
- **Daemon cache cleanup** (`[cache_cleanup]`, on by default): hourly, 72 h age,
  `min_free_gb = 10`, under `remote_base`.
- **Clean-overlay roots** are reaped at teardown after retrieval.
- **Auto-rejoin** refuses to bring a bypassed worker back below 5 GB free.

## Inspect First, Delete Second

Only for what `rch gc` doesn't cover (legacy names, foreign `target_*` trees):

```bash
ssh <user>@<host> 'du -sh /tmp/rch-* /tmp/rch_target_* /data/tmp/rch/* 2>/dev/null | sort -h | tail'
ssh <user>@<host> 'find /data/projects -maxdepth 3 -type d \( -name ".rch-target-*" -o -name "target_rch_*" -o -name "target_*" -o -name "target-*" -o -name target \) -exec du -sh {} + 2>/dev/null | sort -h | tail -n 20'
ssh <user>@<host> 'sudo lsof +D <candidate> 2>/dev/null | head'     # must be empty
rch --json queue | jq -r '.data.active_builds[]?.project_id'          # must not name that project
```

Only when both are empty is a manual removal low-risk — and it still needs
explicit user authorization (AGENTS.md).

## Hand Off to `sbh`

Detect with rch, remediate with `sbh` (disk-pressure defense: ballast, scan,
clean). Pattern:

```bash
worker_host() { rch --json workers list | jq -r --arg id "$1" '.data.workers[] | select(.id==$id) | .host'; }
rch --json status --workers \
  | jq -r '.data.daemon.workers[] | select(.pressure_state!="healthy") | .id' \
  | while read -r w; do h="$(worker_host "$w")"; ssh "ubuntu@$h" 'sbh status --json' 2>/dev/null || echo "($w / $h) — sbh not installed or ssh failed"; done
```

If `sbh` is **not** on a worker, don't write `rm -rf` of your own; install it or
escalate. One agent's `rm -rf` colliding with another agent's active build has
historically been the worst class of incident in this fleet.

## When `sbh` Doesn't Help (RCH-E215 / E216 / E217)

- **E215 reclaim failed** — inspect the largest residents sbh refused (often
  `/var/log/journal`, `~/.cargo/registry`; `cargo cache --autoclean` if present).
- **E216 headroom insufficient** — steer builds elsewhere (`rch workers drain
  <id> -y`) while you free space; raise reservation policy only knowingly.
- **E217 active-build protection** — wait for the build; never override.

## Memory (E214), I/O (E213), Telemetry (E212)

```bash
ssh <user>@<host> 'free -h; cat /proc/pressure/memory; ps -eo pid,user,rss,cmd --sort=-rss | head -15'
```

Runaway `cargo test` → `process-triage` skill; don't `kill -9` blindly.
Repeated E213 without disk pressure → lower `total_slots` on that worker.
E212: `rch-wkr` dead or rebooted → `rch fleet deploy --worker <id> --verify`, or
wait a telemetry tick (~30 s; `[remediation.telemetry_freshness] max_age_secs =
120`); per-worker `pressure_telemetry_fresh` / `pressure_telemetry_age_secs`
in `rch --json status --workers` and the `telemetry_stale` admission token
(`RCH-I008`) are the signals. Windows workers are a permanent, expected
`TelemetryGap`.

## Preventive Hygiene

- Keep `.rchignore` / `[transfer] exclude_patterns` generous (`target/`, `target_*/`, `.rch-target-*/`, `node_modules/`, `dist/`, `.next/`); reload with `rch daemon reload`.
- Don't set a global `CARGO_TARGET_DIR` on a **worker** (see `provision-new-machine`); rch rewrites it per project anyway.
- Consider enabling the periodic reaper on a canary worker (`RCH_WORKER_REAP_ENABLE=1`, `--workers`-scoped `rch gc --dry-run` first).
- Put `TMPDIR=/data/tmp` on workers whose `/tmp` is a small tmpfs.

## Triage Cheat Sheet

```bash
# 1. fleet view
rch status --remediation
rch --json status --workers | jq -r '.data.daemon.workers[] | "\(.id)  \(.pressure_state)  free=\(.pressure_disk_free_gb)GB  io=\(.pressure_disk_io_util_pct)  mem=\(.pressure_memory_pressure)"'
# 2. one worker
ssh <user>@<host> 'df -h / /data /tmp 2>/dev/null; free -h; cat /proc/pressure/memory /proc/pressure/io'
# 3. what rch owns there
rch cache status --workers <id>
rch gc --dry-run --workers <id>
# 4. reap (2.0.0 needs --apply; on 1.0.58 drop it)
rch gc --apply --workers <id>
# 5. still hot → sbh
ssh <user>@<host> 'sbh status --json'
# 6. still hot → drain and investigate
rch workers drain <id> -y ; # ... ; rch workers enable <id>
```
