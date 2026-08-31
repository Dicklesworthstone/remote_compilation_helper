# RCH Operations

## Contents

- [Baseline Runbook](#baseline-runbook)
- [Worker Fleet Lifecycle](#worker-fleet-lifecycle)
- [Fleet Deploy/Rollback](#fleet-deployrollback)
- [Path-Dependency and Multi-Repo Notes](#path-dependency-and-multi-repo-notes)
- [Transfer Stability (Rsync/Artifact Churn)](#transfer-stability-rsyncartifact-churn)
- [Queue and Cancellation Operations](#queue-and-cancellation-operations)
- [Anti-Patterns](#anti-patterns)
- [Debug Command Pack](#debug-command-pack)

## Baseline Runbook

Use this sequence for most production incidents.

### 1) Confirm current posture

```bash
rch check
rch status --workers --jobs
rch workers probe --all
rch queue
```

### 2) Validate config and daemon wiring

```bash
rch config show --sources
rch --json config get general.socket_path
rch --json daemon status
rch config doctor
```

### 3) Validate hook routing

```bash
rch hook status
rch agents status
rch hook test
```

### 4) Validate offload path directly

```bash
rch diagnose --dry-run "cargo check --workspace --all-targets"
rch admit "cargo check --workspace --all-targets"
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose rch exec -- cargo check --workspace --all-targets
```

If step 4 prints `[RCH] remote <worker> (...)`, RCH infrastructure is healthy and remaining failures are project/toolchain specific (or interception-side: `rch shim status`, hook). A refusal line names what is missing.

### 5) If workers show storage pressure, inspect the right filesystem

RCH pressure warnings often come from `/` while the immediate churn lives in `/tmp`. Check both before deciding whether the host actually needs intervention:

```bash
ssh ubuntu@<host> 'df -h / /tmp'
ssh ubuntu@<host> 'free -h && cat /proc/pressure/memory && cat /proc/pressure/io'
```

Then let rch enumerate and reap what it owns (pooled `.rch-target-*-pool-*`
dirs, per-job dirs, tmp-base strays) before touching anything by hand:

```bash
rch status --remediation                   # "Disk Pressure … tightest free-disk ratio"
rch cache status --workers <id>            # read-only per-dir verdicts
rch gc --dry-run --workers <id>            # what the sweep would remove
rch gc --workers <id>                      # remove (pass --workers; sweeping all can hang — open bug)
```

Only for legacy/foreign trees rch doesn't own:

```bash
ssh ubuntu@<host> 'du -sh /tmp/rch-* /tmp/rch_target_* /data/tmp/rch/* 2>/dev/null | sort -h'
ssh ubuntu@<host> 'find /data/projects -maxdepth 3 -type d \( -name ".rch-target-*" -o -name "target_rch_*" -o -name "target_*" -o -name target \) -exec du -sh {} + 2>/dev/null | sort -h | tail -n 20'
ssh ubuntu@<host> 'sudo lsof +D <candidate>'      # must be empty
rch --json queue | jq -r '.data.active_builds[]?.project_id'   # must not name that project
```

Only treat empty `lsof` + no active build as a low-risk cleanup signal — and it still needs explicit user authorization. Full guide: `DISK_AND_PRESSURE.md`.

### 6) If `rch exec` fails at sync time, verify remote mirror ownership

When the canonical worker mirror under `/data/projects/<repo>` is owned by `root` or another account, rsync fails with `Permission denied` or `Operation not permitted`.

Check:

```bash
ssh ubuntu@<host> "stat -c '%U:%G %a %n' /data/projects/<repo>"
```

Fix:

```bash
ssh ubuntu@<host> 'sudo chown -R ubuntu:ubuntu /data/projects/<repo> && sudo chmod 775 /data/projects/<repo>'
```

After the fix, rerun:

```bash
rch diagnose --dry-run "cargo build --release"
rch exec -- cargo build --release
```

---

## Worker Fleet Lifecycle

### Discovery and setup

```bash
rch workers discover
rch workers discover --probe
rch workers discover --add --yes
rch workers setup --all
```

### Runtime management

```bash
rch workers list --speedscore
rch workers capabilities --refresh
rch workers benchmark --all --force
rch workers compare <id> <id>
rch status --fleet                     # desired vs live (bypassed / disabled / unreachable / missing)
rch workers drain <worker> -y
rch workers enable <worker>            # also clears a temporary-bypass record
rch workers disable <worker> --reason "maintenance" --drain -y
```

### Toolchain/binary synchronization

```bash
rch workers sync-toolchain --all
rch workers deploy-binary --all
```

---

## Fleet Deploy/Rollback

```bash
rch fleet status
rch fleet deploy --verify
rch fleet deploy --canary 25 --canary-wait 60 --verify
rch fleet rollback --verify
rch fleet history --limit 20
```

For large fleets:

- Prefer canary first, then full rollout.
- Use `--dry-run` before disruptive operations.
- Use `--drain-first` if workers are heavily loaded.

---

## Path-Dependency and Multi-Repo Notes

RCH now supports dependency-closure planning and canonical topology handling, but path-based workspaces still require worker-accessible sibling repos.

Recommended checks:

```bash
rch diagnose --dry-run "cargo test --workspace"
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --workspace --no-fail-fast
rch sync --worker <id> --project .             # preview stale-cache resync; --force applies
```

If remote path dependencies are missing or stale (`RCH-E410..E414`):

- Ensure required sibling repos exist on worker hosts under canonical project roots.
- `rch sync --force --worker <id>` to invalidate a stale worker cache for the closure.
- Re-run `rch workers setup --all` and then retry the `rch exec -- ...` command.

While a closure build runs, rch holds `flock`s on every mutable closure root on
the worker until Cargo exits; a second agent's build on a shared sibling waits
(`[RCH] waiting for N remote source-authority lock(s)`), it is not hung.

---

## Transfer Stability (Rsync/Artifact Churn)

If sync fails due to active artifact churn, extend transfer excludes:

```toml
[transfer]
exclude_patterns = [
  "target/",
  "target_*/",
  "target-*/",
  ".cargo-target/",
  ".cargo-target-*/",
]
```

Then reload daemon config:

```bash
rch daemon reload
rch config show --sources
```

Operational notes:

- Don't hand-pick remote target dirs: `CARGO_TARGET_DIR` (and `TMPDIR`, Go caches) are rewritten on the worker to managed pooled paths under the project mirror regardless of what you pass. `RCH_DISABLE_TARGET_REUSE=1` only switches pooled → per-job.
- If the working tree itself cannot sync because the remote canonical mirror is broken, either repair ownership on the worker (§6 above; a fleet-wide `rch doctor --reliability --scope ownership` probe exists on main only) or temporarily build from a clean directory under the canonical root (`/data/projects`), not `/tmp`.
- For builds that must not see other agents' uncommitted edits, use `rch exec --base HEAD --clean-overlay …` (`EXEC_MODES.md`).
- Payload caps (`transfer skipped`): `[transfer] max_transfer_mb` / `max_transfer_time_ms`; per-attempt upload budget `RCH_SYNC_TIMEOUT_MS`.

---

## Queue and Cancellation Operations

```bash
rch queue
rch queue --watch
rch cancel <build-id>
rch cancel --all --yes
```

Use cancellation when builds are wedged or backlog pressure is starving high-priority work.

---

## Anti-Patterns

| Don't | Why | Do Instead |
|-------|-----|------------|
| Assume remote failures mean local failures | Some failures are worker/config topology issues | Validate with `rch diagnose` + `rch exec -- ...` |
| Hardcode `/tmp/rch.sock` in runbooks | Default socket may be runtime/cache path | Query via `rch --json daemon status` |
| Skip `rch check` and jump to manual SSH surgery | Loses quick signal on daemon/hook/worker health | Start with `rch check` and `rch status --workers --jobs` |
| Ignore queue pressure | Can cascade into timeouts and local fallback | Monitor `rch queue --watch` and cancel stale builds |
| Apply broad/destructive worker cleanup | Risks collateral damage | Prefer targeted fixes + `workers setup`/`fleet` commands |
| Assume `/tmp` pressure and `/` pressure are the same problem | They often are not; fixing the wrong one wastes time | Check `df -h / /tmp` and inspect the matching artifact surface |
| Delete large build dirs without checking for open files | Risks breaking active remote builds | `rch gc --dry-run --workers <id>` first; manual `rm` only after `lsof` and `rch queue` are clear |
| Chain cargo commands in a shell string (`rch exec -- bash -lc "cargo a && cargo b"`) | Refused with `RCH-E301`; rch can't bind the output path | Separate `rch exec -- cargo …` invocations |
| `rch daemon restart -y` while `rch queue` shows active builds | It interrupts them (`-y` only skips the warning); the daemon may answer `shutdown_blocked` | Wait for 0 active builds or `rch cancel` first |
| Uninstall the shim because a build exited 103 | 103 means the *fleet* had nothing admissible | `rch status --remediation`, fix, retry |
| Prefix `RCH_ENABLED=0` inside an agent command to "go local" | The hook rewrites it anyway | `.rch/config.toml` `force_local = true` + `RCH_CARGO_WRAPPER_BYPASS=1` (`SHIM.md`) |
| Hand-tune `priority`/`total_slots` | Inverts capacity silently | Benchmark, verify scores differ, then set (`SKILL.md`) |

---

## Debug Command Pack

```bash
RCH_LOG_LEVEL=debug rch diagnose "cargo build --release"
RCH_LOG_LEVEL=debug rch check
rch status --remediation
rch --json status --fleet > /tmp/rch-fleet.json
rch doctor --json > /tmp/rch-doctor.json
rch doctor --reliability --scope all --json > /tmp/rch-reliability.json
rch --json workers probe --all > /tmp/rch-workers-probe.json
rch shim status --json
rch daemon logs -n 200
rch error explain <RCH-Exxx|RCH-Innn>
rch doctor --runbook RCH-R006            # authored runbook for the reason code you saw
```
