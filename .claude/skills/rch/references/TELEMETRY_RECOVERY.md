# Telemetry Database Corruption Recovery

## Contents

- [Symptom Signatures](#symptom-signatures)
- [Recovery (Safe)](#recovery-safe)
- [Verify Integrity Before Acting](#verify-integrity-before-acting)
- ["Telemetry protocol version mismatch"](#telemetry-protocol-version-mismatch)
- [Prevention](#prevention)
- [When the Recovery Doesn't Stick](#when-the-recovery-doesnt-stick)

The rch telemetry SQLite database lives in the platform data dir (`ProjectDirs("com","rch","rch").data_local_dir()`): **Linux** `~/.local/share/rch/telemetry/telemetry.db`, **macOS** `~/Library/Application Support/com.rch.rch/telemetry/telemetry.db`. The commands below use `$RCH_TELEMETRY_DIR`; set it first:

```bash
case "$(uname -s)" in Darwin) RCH_TELEMETRY_DIR="$HOME/Library/Application Support/com.rch.rch/telemetry" ;; *) RCH_TELEMETRY_DIR="$HOME/.local/share/rch/telemetry" ;; esac
```

Like any SQLite file under heavy concurrent write load, it can occasionally corrupt — most often after host crashes, OOM-kills, or disk-full incidents.

This is one of the cliffs agents previously fell off (cass evidence: 30+ incidents under "Telemetry database integrity check failed"). The recovery is mechanical and safe — but the skill never previously documented it.

---

## Symptom Signatures

Any of:

- `[RCH-E507] Metrics collection error` recurring in `rch daemon logs`
- `Telemetry database integrity check failed` log lines
- `Telemetry protocol version mismatch` (related; less common)
- `rch speedscore --all` returns empty or stale data
- `rch self-test history` returns empty even though you know runs happened
- `database disk image is malformed` in daemon stderr

`rch doctor` may or may not catch this (depends on version).

---

## Recovery (Safe)

Telemetry is **purely derived data**. Losing it loses historical SpeedScores and build durations, but nothing operationally critical.

```bash
# 1. Stop the daemon ONLY when no builds are active — stop/restart interrupt builds, they do not drain
#    (run these as a script, or paste line by line — the guards below STOP, do not continue past a failed guard)
rch --json queue | jq -e '.data.active_builds|length == 0' >/dev/null || { echo "STOP: builds active; wait or rch cancel" >&2; false; }
rch daemon stop -y
rch --json daemon status | jq -e '.data.running == false' >/dev/null || { echo "STOP: daemon still running (shutdown_blocked?)" >&2; false; }

# 2. Move the corrupt db aside (don't delete; you might want it for forensics)
ts=$(date +%s)
for f in telemetry.db telemetry.db-wal telemetry.db-shm; do
  [ -e "$RCH_TELEMETRY_DIR/$f" ] && mv "$RCH_TELEMETRY_DIR/$f" "$RCH_TELEMETRY_DIR/$f.broken-$ts"
done

# 3. Restart — the daemon recreates the schema on first write
rch daemon start
sleep 2
rch check
```

Verify:

```bash
ls -la "$RCH_TELEMETRY_DIR"/            # new telemetry.db should exist
rch --json daemon status | jq '.data.running'
rch --json status | jq -r '.data.daemon.daemon.version'   # daemon version lives here, not in `daemon status`
```

Related but different: `rch doctor --reliability --scope pressure` reports
telemetry staleness per worker (`RCH-R1xx`; `rch --json status --workers`
carries `pressure_telemetry_fresh` / `pressure_telemetry_age_secs`). Windows
workers report no telemetry in practice — the collectors are `/proc`-based — so they show a permanent `TelemetryGap` (a soft selection penalty, not an exclusion);
macOS workers collect without `/proc` since v1.0.57 (`d64190d`).

You'll lose:
- SpeedScore history (`rch speedscore --history`) — rebuilds on subsequent self-tests
- Self-test history (`rch self-test history`) — same

You will NOT lose:
- Worker config
- Daemon config
- Hook installs
- Active builds — but only because step 1 waited for the queue to be empty; a stop with builds active interrupts them

---

## Verify Integrity Before Acting

Before assuming the db is broken, check it directly:

```bash
sqlite3 "$RCH_TELEMETRY_DIR/telemetry.db" 'PRAGMA integrity_check;'
```

If that prints `ok`, the corruption is elsewhere — probably the daemon process is wedged on a different bug. Capture diagnostics and consider `Playbook B` in `RECOVERY_PLAYBOOKS.md` instead.

If it prints any error or hangs, the db is genuinely corrupt — proceed with the move-aside recovery.

---

## "Telemetry protocol version mismatch"

This is different — it means a worker is running a `rch-wkr` whose telemetry schema doesn't match the daemon's. The fix is to redeploy the worker binary:

```bash
rch fleet status                    # confirm version drift
rch fleet deploy --canary 25 --canary-wait 60 --verify
rch fleet deploy --verify           # full
```

If only one worker is affected:

```bash
rch fleet deploy --worker <id> --verify
```

---

## Prevention

- Don't stop the daemon while builds are in flight. On 1.0.58 `rch daemon stop`/`restart` interrupt them (`-y` only skips the warning); on 2.0.0 they refuse unless `--drain` or `--force`. Check `rch queue` first.
- Watch disk pressure on the host (not just on workers — the host runs the daemon and the telemetry db). `df -h "$RCH_TELEMETRY_DIR"` should never be near full.
- If you're upgrading rch on the host, restart the daemon afterwards (`rch daemon restart -y`). The `daemon_installs_hooks` self-healing covers one direction, but version drift on the daemon binary is independent.

---

## When the Recovery Doesn't Stick

If you move the file aside and the new db corrupts again within minutes, you have a deeper issue — disk failure, kernel-level bug, or another process writing to the same file. Capture:

```bash
journalctl -k --since "1 hour ago" | grep -iE 'i/o|sata|nvme|memory'   # Linux
sudo dmesg | tail -50
df -h "$RCH_TELEMETRY_DIR"
mount | grep "$(df -P "$RCH_TELEMETRY_DIR" | awk 'NR==2{print $1}')"     # portable (no GNU stat -c)
```

…and escalate. This is filesystem-level; the rch skill has done what it can.
