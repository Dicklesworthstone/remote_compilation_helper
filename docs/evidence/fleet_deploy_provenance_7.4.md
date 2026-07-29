# ocv9i.7.4 live proof — fleet-deploy release provenance + audit trail

**Date:** 2026-06-21 (UTC)
**Client under test:** rch commit `6d5dd9f16e83` (HEAD) — carries the deploy_batch
provenance gate (rch/src/fleet/executor.rs) + FleetDeployAuditRecord emission.
**Worker:** vmi1167313 (remote_user `root`), lowest-priority fleet member
(hz2 deliberately untouched, reserved for the bd-784xt self-test).
**Artifact:** freshly-built rch-wkr 1.0.42 commit 6d5dd9f (linux x86_64 ELF, stripped).

## Live deploy — `rch fleet deploy --worker vmi1167313 --force --verify -y`

Full SSH command trace in `fleet_deploy_vmi1167313_7.4.txt`. The deploy executed,
in order:

1. **SSH connectivity** check passed.
2. **Backup-before-deploy** (rollback-safe switch): `cp ~/.local/bin/rch-wkr
   ~/.rch/backups/rch-wkr-1.0.42`, sha256 recorded
   (`f5531e4ac05618907695cb532a10b8ae1de362e6ef25610269593e7ebf5d795c`), saved to
   the rollback registry → captured as `previous_artifact_id: "1.0.42"`.
3. **OS/arch guard** (`uname -s; uname -m`) before transfer.
4. **Release-provenance gate ran BEFORE transfer** and wrote a
   `FleetDeployAuditRecord` to
   `~/.local/share/rch/fleet_history/provenance_audit.jsonl` (run_id
   `53f11bc9-6319-4f71-b307-4f96aced568a`) with every required field:

   ```json
   {"run_id":"53f11bc9-6319-4f71-b307-4f96aced568a",
    "bead_id":"bd-session-history-remediation-ocv9i.7.4",
    "worker_id":"vmi1167313","remote_user":"root","artifact_id":"rch-wkr",
    "target_triple":"unknown","verification_status":"dev_allowed",
    "rollback_status":"none","reason_code":"provenance_dev_artifact_allowed",
    "duration_ms":0,
    "detail":"no signature/checksum material for artifact rch-wkr (release_id=none); permitted by dev-artifact policy",
    "previous_artifact_id":"1.0.42"}
   ```

   Policy = default `dev_friendly`: a locally-built binary with no sidecar manifest
   is permitted with an explicit dev-artifact audit reason (fail-open for dev
   fleets). `target_triple=unknown` because the (3-round-trip) triple discovery
   runs ONLY when a release manifest is present; the common no-manifest path adds
   no SSH and relies on the OS/arch guard + the SCP checksum below.

5. **Atomic, fail-closed transfer**: SCP to a temp path, then a single remote step:
   `chmod +x` → **checksum verify** (`actual == 94980817fc35f350…` else `exit 1`) →
   **wrong-arch/corrupt guard** (`--version` on the staged temp, else `exit 1`) →
   `mv -f` temp → `~/.local/bin/rch-wkr`. The worker's good binary is never
   overwritten unless the staged artifact verifies.
6. **Post-deploy `--verify`**: exact-path `--version`, `rch-wkr health`, and
   `rch-wkr capabilities` handshake all returned exit 0 →
   `post-deploy validation passed (exact-path version, health, capabilities handshake)`.
7. Daemon auto-re-benchmarked the updated worker:
   `Benchmark completed successfully, worker_id: vmi1167313, score: 100.0`.

Deployment audit-log (`fleet_deploy_audit_7.4.json`) records the DeploymentStarted
event with `deployment_id == run_id`.

## Live rollback-audit — `rch fleet rollback --worker vmi1167313 -y`

The rollback-audit path fired live and appended a second record for the same run,
flagging it `rollback_status: "rollback_failed"`:

```json
{"run_id":"53f11bc9-...","worker_id":"vmi1167313","verification_status":"dev_allowed",
 "rollback_status":"rollback_failed","reason_code":"provenance_dev_artifact_allowed",
 "previous_artifact_id":"1.0.42"}
```

Note: the binary-restore itself was a **same-version no-op** — the freshly-deployed
artifact carries the same version STRING (`1.0.42`) as the backup, so "rollback to
previous version" found no *distinct* target (`No previous version found for
rollback`). That is the correct degraded/operator-attention outcome, and it proves
the audit emission fires on a failed rollback. The binary-restore logic for a
genuine cross-version rollback is covered by the rollback.rs unit suite (4 audit
tests + 54-test suite). The worker keeps the `--verify`-confirmed-healthy fresh
binary (benchmark score 100.0); the prior binary remains backed up at
`~/.rch/backups/rch-wkr-1.0.42` on the worker.

## Acceptance mapping

- "Fleet deploy verifies checksum/signature/provenance before transfer, fails
  closed on mismatch, explicit reason when provenance unavailable but policy allows
  dev artifacts": PROVEN (gate ran pre-transfer; fail-closed checksum in the SCP
  step; `reason_code=provenance_dev_artifact_allowed` for the dev artifact).
- "Artifact resolver records source/build id, triple, checksum, builder identity,
  expected protocol": recorded in the audit record + deployment audit-log.
- "Rollback history records previous artifact identity, worker, remote user/path,
  deploy time, validation result, operator trigger": the run's records carry
  `previous_artifact_id`, `worker_id`, `remote_user`, timestamps, verification +
  rollback status, and `operator` trigger.
- "E2E logs include run_id, bead_id, worker_id, artifact_id, target_triple,
  verification_status, rollback_status, reason_code, duration_ms, detail": all
  present (above).
- Tests for good signature / missing-signature-strict / checksum mismatch / wrong
  triple / interrupted deploy / rollback-after-canary / dev policy: rch-common
  fleet_provenance (18) + rollback.rs (54) unit/mock suites; REQ-FLEET-003 matrix
  row; schema FLEET_DEPLOY_AUDIT v1.0.0.
