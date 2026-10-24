# RCH Error, Incident, and Runbook Codes

## Contents

- [Three Namespaces](#three-namespaces)
- [Live Catalog](#live-catalog)
- [`RCH-Ennn` Categories](#rch-ennn-categories)
- [High-Frequency `RCH-Ennn` Codes](#high-frequency-rch-ennn-codes)
- [`RCH-Innn` Incident / Refusal Reason Codes](#rch-innn-incident--refusal-reason-codes)
- [`RCH-Rnnn` Reliability Reason Codes and Runbooks](#rch-rnnn-reliability-reason-codes-and-runbooks)
- [Exit Codes Are Three Schemes](#exit-codes-are-three-schemes)
- [Cross-References](#cross-references)

## Three Namespaces

| Namespace | Meaning | Source of truth |
|---|---|---|
| `RCH-Ennn` | expected, explainable failures (100 catalogued in 1.0.58 — `rch schema list` prints the live count — plus extended miette ranges) | `rch-common/src/errors/catalog.rs`, `rch/src/error.rs` |
| `RCH-Innn` | incident / admission-refusal reason codes (18; stable, append-only) | `rch-common/src/incident.rs` |
| `RCH-Rnnn` | reliability diagnostics from `rch doctor --reliability` / `rch status`, some with authored runbooks | `rch-common/src/errors/reliability.rs` |

They appear in `[RCH] remote <worker> failed [RCH-Exxx] …`, `[RCH] local
(dependency preflight RCH-Exxx: …)`, requested-worker refusals `[RCH-Innn] …`,
`rch doctor --json` (`.checks[].code`), `rch --json` error envelopes
(`.error.code`), the exec envelope (`error_code`), and daemon logs. Treat the
code as the stable handle; wording changes between releases.

## Live Catalog

```bash
rch error list                          # 166 known codes on 1.0.58 (100 E + 18 I + 48 R; the R bands below are sparse); 177 on 2.0.0 (102 E + 18 I + 57 R)
rch error list --category disk_pressure # snake_case categories: config, network, worker, build, transfer, internal, admission, ...
rch error explain RCH-E309              # message, category, remediation
rch error explain RCH-I001 --json
rch schema export -o /tmp/rch-schemas && jq -r '.errors[] | "\(.code) | \(.message)"' /tmp/rch-schemas/error-codes.json | sort
```

## `RCH-Ennn` Categories

| Range | Category | Sub-ranges |
|---|---|---|
| 001–099 | Config | 013–018 path-deps, 019–024 closure planning |
| 100–199 | Network | SSH, DNS, TCP |
| 200–299 | Worker | 210–219 storage/pressure |
| 300–399 | Build | 310–317 process triage, 320–325 cancellation, 329 workspace inheritance |
| 400–499 | Transfer | 410–414 **dependency preflight** (missing/stale/unknown/policy/timeout) |
| 500–599 | Internal | daemon socket/protocol, IPC, hook, metrics, logging, update |
| 600–925 | Extended (miette, not in the catalog enum) | 600 platform (`UnixOnly`, `WindowsOnly`, `BinaryNotFound`, `UnixSocketUnsupported`), 700 fleet, 800 binary, 900 web, 910 completions, 920 editor |

Anything ≥ 600 is bucketed as `internal` by `category()`.

## High-Frequency `RCH-Ennn` Codes

### Config

| Code | Meaning | First action |
|---|---|---|
| E001 | Config file not found (also: invalid `--result-dir`, exit 2) | `rch config init`; for exec: make `--result-dir` repo-relative |
| E003 | Invalid TOML | `rch config validate` |
| E007 | No workers configured | `rch workers discover --add --yes && rch workers setup --all` (or `rch workers init`) |
| E008 | Worker config invalid | `rch config doctor` names the bad `[[workers]]` block |
| E009 | SSH key path invalid | check `identity_file`; `chmod 600`; `SSH_KEY_RECOVERY.md` |
| E013–E018 | Path-dep manifest/metadata problems | `PATH_DEPENDENCIES.md` |
| E016 | Path dep outside canonical root | move it, or widen `[path_topology] canonical_root` |
| E019–E024 | Closure plan failed / fail-open / high-risk / missing / non-deterministic / fingerprint mismatch | `RCH_LOG_LEVEL=debug rch diagnose --dry-run "<cmd>"` |

### Network

| Code | Meaning | First action |
|---|---|---|
| E100 / E101 | SSH connect / auth failed | `ssh -v -i <key> <user>@<host> true`; `SSH_TUNING.md` |
| E102 | Key not found / bad format | `ls -la`, `head -1` the key |
| E103 | Host key changed | compare `ssh-keygen -F` vs `ssh-keyscan`; refresh only with authorization |
| E104 / E105 | Command timeout / session dropped | `RCH_SSH_SERVER_ALIVE_INTERVAL_SECS=15` |
| E108 / E109 | Refused / TCP timeout | sshd down, port, firewall |

### Worker

| Code | Meaning | First action |
|---|---|---|
| E200 | No workers available (maps I001) | `rch status --fleet`; `rch admit "<cmd>"` |
| E202 / E203 | Health check / self-test failed | `rch workers probe <id>`; `rch self-test --worker <id>` |
| E204 | At capacity (maps I003) | queueing is default; raise `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS` or `total_slots` |
| E205 | Missing toolchain/component (maps I006) | `rch workers sync-toolchain --all`; if *every* worker fails with "missing clippy, rustfmt", the worker's `rchd`/`rch-wkr` runs with a PATH lacking `~/.cargo/bin`; the PATH-fallback fix (commit `82b1033`, 2026-08-23) is **post-1.0.58** (shipped in 1.0.59), so until 1.0.59 or later is deployed put rustup on the dispatch user's non-login PATH (`/root/.zshenv` per `provision-new-machine`) |
| E207 | Circuit open (maps I009) | auto-closes after cooldown; `rch workers enable <id>` after fixing the cause |
| **E210 / E211** | Disk critical / warning | `DISK_AND_PRESSURE.md`; `sbh` |
| E212 | Telemetry gap (maps I008) | wait a tick; check `rch-wkr` on the worker |
| E213 / E214 | I/O / memory pressure | transient; `process-triage` |
| E215–E217 | Reclaim failed / headroom insufficient / active-build protection | `DISK_AND_PRESSURE.md` |

### Build

| Code | Meaning | First action |
|---|---|---|
| E300 | Remote compilation failed | read the compiler error on stderr |
| **E301** | `BuildUnknownCommand` — the **shell-wrapped cargo refusal** (`bash -lc "cargo …"`) and the strict-remote `[RCH-E301] (non-compilation command)` refusal, exit 1 | split into direct `rch exec -- cargo …` invocations; real non-compilation work → `rch exec --job` |
| E303 | Build timeout | raise `[compilation] build_timeout_sec` / `test_timeout_sec` |
| E305 | Remote working dir error | mirror perms — `OPERATIONS.md` chown recipe |
| E307 | Build env setup failed | missing system package on the worker (auto-detected from `pkg-config` / `.pc` mentions) |
| **E309** | Artifact / declared result dir missing or partial → exit **102** (maps I014) | remote command succeeded; retry retrieval; check `--result-dir` paths exist on the worker |
| E320–E325 | Cancellation lifecycle (graceful sent, escalated kill, remote kill failed, cleanup failed, slot leak, timeout) | `MULTI_AGENT_CONTENTION.md` |
| E329 | Cargo workspace inheritance problem | fix `workspace = true` inheritance in the manifest |

### Transfer

| Code | Meaning | First action |
|---|---|---|
| E400 | rsync failed | `rch daemon logs -n 200` |
| E401 | Sync timed out | `RCH_SYNC_TIMEOUT_MS` (per attempt), tighten excludes |
| E402 | Source vanished mid-rsync (maps I013) | another agent edited the tree; retry or use `--clean-overlay` |
| E404 | Worker disk full (maps I016) | `DISK_AND_PRESSURE.md` |
| E405 | Permission denied | mirror ownership — `OPERATIONS.md` |
| E406 | Checksum mismatch | concurrent writes; `MULTI_AGENT_CONTENTION.md` |
| E410–E414 | Dependency preflight missing / stale / unknown / policy / timeout | `PATH_DEPENDENCIES.md`; `rch sync --force` for stale worker caches |

### Internal

| Code | Meaning | First action |
|---|---|---|
| E500 / E502 | Daemon socket / not running (maps I010) | `rch daemon start`; `SELF_HEALING.md` |
| E506 | Hook execution failed | `RCH_LOG_LEVEL=debug rch hook test` |
| E507 | Metrics/telemetry error | `TELEMETRY_RECOVERY.md` |
| E509 | Update error | `rch update --check`; installer no longer downgrades (rate-limit fix) |

## `RCH-Innn` Incident / Refusal Reason Codes

| Code | Class | Maps to | You will see it when |
|---|---|---|---|
| I001 | no admissible workers | E200 | every candidate rejected; also the daemon-selected-unrequested-worker refusal under `RCH_WORKER` |
| I002 | critical pressure | E210 | requested/only worker is under critical disk pressure |
| I003 | insufficient slots | E204 | requested worker has no free slots (queue with `RCH_QUEUE_WHEN_BUSY=1`) or fewer total slots than `-j` |
| I004 | hard preflight | — | topology / preflight / convergence / reliability probe failed |
| I005 | active project exclusion | — | the worker already runs this project (job mode queues instead) |
| I006 | missing runtime/toolchain/target | E205 | worker lacks bun/go/nix/rust target/component |
| I007 | OS/arch mismatch | — | `--target` triple vs. declared `os` |
| I008 | telemetry stale | E212 | |
| I009 | circuit open / temporary bypass | E207 | worker in quarantine; wait for auto-rejoin |
| I010 | daemon socket refused | E500 | |
| I011 | local fallback | — | recorded in the incident ledger for every fail-open |
| I012 | proof refusal | — | strict-remote / non-compilation refusal |
| I013 | rsync vanished file | E402 | |
| I014 | artifact miss | E309 | |
| I015 | queue ambiguity | — | |
| I016 | disk full | E404 | |
| I017 | wrong user/path worker binary | — | `rch-wkr` installed for a different user/PATH than the daemon dispatches as |
| I018 | toolchain drift (advisory) | — | |

Requested-worker refusals (`RCH_WORKER=<id>`) always pair the code with a
concrete `next_action` (e.g. "pass `-j <total>` or request a larger worker",
"queue with `RCH_QUEUE_WHEN_BUSY=1`", "run `rch diagnose -- <command>`").

## `RCH-Rnnn` Reliability Reason Codes and Runbooks

| Band | Class |
|---|---|
| R001–R014 | Topology (workers configured/unhealthy/unreachable, daemon status, circuit) |
| R100–R105 | Disk pressure tiers + telemetry |
| R200–R204 | Process triage / cancellation debt |
| R300–R305 | Repo convergence |
| R400–R402 | Helper compatibility (rsync / ssh / cargo / zstd) |
| R500–R511 | Rollout posture / config load |
| R600–R601 | Schema compatibility (cross-binary drift) |
| R700–R704 | Mirror ownership (worker mirror-tree ownership drift, detection only; the `ownership` doctor scope is post-1.0.58, present in 2.0.0) |

Authored runbooks (`rch doctor --runbook-list` on 1.0.58, 2026-08-25): R002
NoWorkersConfigured, R004 DaemonStatusUnavailable, R006 AllWorkersUnhealthy,
R007 PartialWorkerCapacity, R009 WorkerCircuitOpen, R010 WorkerUnreachable,
R101 WorkerDiskPressureCritical, R301 RepoConvergenceFailed, R401 HelperMissing,
R504 ConfigLoadFailed; 2.0.0 adds R701 WorkerMirrorOwnershipDrift. Render one
with `rch doctor --runbook RCH-R006` (no probes run). Note: the R002 runbook
text still says `rch workers add <hostname>`, a command that does not exist —
use `rch workers init` / `rch workers discover --add`.

## Exit Codes Are Three Schemes

Do **not** treat 100/101/102 as one scheme:

| Code | `rch exec` / hook path | CLI subcommands (`rch/src/state/exit_codes.rs`) | agent capabilities table (`rch capabilities --json`) |
|---|---|---|---|
| 0 | success | success | success |
| 1 | build error, or permanent fail-closed refusal (`RCH-E301`, `non-compilation command`, `config unavailable`) | general error | general error / degraded health |
| 2 | invalid `--result-dir` (`RCH-E001`) | — | usage error / `rch check` not ready |
| 64 / 78 | — | usage / config (sysexits) | — |
| 100 | — | needs setup | network/SSH failure |
| 101 | `cargo test` failures | daemon down | worker error |
| 102 | artifacts / result dirs not transferred back (`RCH-E309`) | no workers | remote build failed |
| 103 | **retryable** fail-closed refusal (strict remote) | already current (`rch update`) | — |
| 104 / 105 | — | locked / needs migration | — |
| 128+N | killed by signal N | | |

Worker-side (`rch-wkr`): 121 prepare failed, 122 output truncated. rsync 23/24
(partial / vanished) are handled internally.

## Cross-References

- Path-dep family (E013–E024, E410–E414): `PATH_DEPENDENCIES.md`
- Disk-pressure family (E210–E217, R100–R105, I002, I016): `DISK_AND_PRESSURE.md`
- SSH family (E100–E109): `SSH_TUNING.md`, `SSH_KEY_RECOVERY.md`
- Selection / admission (E200–E209, I001–I009): `FAIL_OPEN.md`
- Exec refusals (E301, E309, exit 103): `EXEC_MODES.md`
- Daemon/internal (E500–E509, I010): `SELF_HEALING.md`, `OPERATIONS.md`
