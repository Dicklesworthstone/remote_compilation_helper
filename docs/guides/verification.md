# Verifying RCH Is Working

RCH is intentionally quiet when it succeeds. Use the checks below to confirm
remote compilation is actually happening.

## Quick Checks (2 minutes)

```bash
# Is the hook installed?
rch hook status

# Is the daemon up and reachable?
rch daemon status

# Do you have healthy workers?
rch status --workers

# Do you see active/recent builds?
rch status --jobs
```

If `rch status --jobs` shows active builds while you compile, RCH is
successfully offloading.

## Watching Builds in Real Time

### TUI Dashboard

```bash
rch dashboard
```

This shows live worker status, active builds, and recent history.

### Fleet Dashboard

```bash
rch config set dashboard.url https://rch-fleet.vercel.app   # once
rch web                                                      # opens it
rch web --no-open                                            # just print the URLs
```

The dashboard is the encrypted static console under `dashboard/` (see
`dashboard/README.md`). Agents should read `<url>/api/fleet?view=help`. For live
per-machine state without the snapshot lag, enable the daemon's tailnet API
(`[api]` in the configuration guide) and query `http://<tailscale-ip>:9101/status`.

### CLI Watch Loop

```bash
# Refresh every second (Linux/macOS)
watch -n 1 rch status --jobs
```

## Build History and Stats

RCH tracks recent builds via the daemon status API.

```bash
# Recent builds + active builds
rch status --jobs

# Aggregate stats (success rate, durations)
rch status --stats
```

The TUI dashboard also includes a build history panel.

## Verbose / Diagnostic Modes

Use these when you need to see why a command is or is not being offloaded.

```bash
# Verbose CLI output
rch --verbose status --jobs

# Run the hook classifier directly (no execution)
rch hook test

# Explain classification and worker selection
rch diagnose "cargo build --release"
```

For deeper logs:

```bash
# Hook + CLI logging
RCH_LOG_LEVEL=debug rch status --jobs

# Daemon logging (foreground)
RCH_LOG_LEVEL=debug rchd
```

## Signs It's Working

- Builds are noticeably faster than local builds.
- `rch status --jobs` shows active or recent remote builds.
- Worker slots decrease during a compile.
- The TUI/Web dashboards show active builds and worker utilization.

## Signs It's Not Working

- Builds take the same time as before with no slot usage.
- `rch daemon status` reports not running.
- `rch status --workers` shows all workers unreachable.
- `rch hook status` says the hook is not installed.

## If Something Looks Wrong

```bash
# Validate SSH and worker connectivity
rch workers probe --all

# Full diagnostics
rch doctor
```

If the daemon is down, start it with `rchd` or `rch daemon start`.
