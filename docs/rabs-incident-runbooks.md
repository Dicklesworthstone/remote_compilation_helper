# RABS Incident Runbooks (bead R008)

Machine-readable twin: `rabs-protocol/src/incident_bundle.rs` — a
test pins every class anchor below against that registry, so these
runbooks cannot drift from the code. Each incident class has six
facets: detection signal, automatic containment, operator commands,
evidence bundle, recovery path, and a regression-test requirement
(an incident is not closed until its regression test exists).

## incorrect-result-divergence

- **Detect:** F022/J016 differential mismatch, or a same-key
  candidate classifying `SemanticDivergence` (A018).
- **Contain:** automatic — quarantine the ACTION key; serving for it
  stops fleet-wide; both candidates preserved.
- **Operate:** `rch why action KEY`; `rch inspect action KEY`;
  compare the two attempt evidence bundles.
- **Evidence:** both canonical manifests, both attempt evidence
  bundles, the key breakdown, the projection decision.
- **Recover:** root-cause the unsound key component; ship the key
  fix; epoch-bump if the fix changes key semantics; un-quarantine.
- **Regression:** a fixture reproducing the divergence must land
  red-then-green with the fix.

## object-corruption

- **Detect:** digest mismatch on read/verify (F024 hit verification),
  or the T044 collision quarantine firing.
- **Contain:** automatic — the object is quarantined (never served);
  peers re-fetch from source.
- **Operate:** `rch inspect object DIGEST`; check storage health.
- **Evidence:** the stored bytes (quarantined copy), expected digest,
  observed digest, storage-path metadata.
- **Recover:** re-ingest from an authoritative source; if disk-level,
  run storage diagnostics before re-admitting the volume.
- **Regression:** corruption-injection fixture over the read path.

## publication-fence-violation

- **Detect:** a publication attempt with a stale boot generation /
  incarnation (F029) or after an F031 tombstone.
- **Contain:** automatic — the publication refuses (fenced); the
  worker's lease is not renewed.
- **Operate:** `rch why worker DECISION-ID`; inspect fence sequence.
- **Evidence:** the fencing tokens (expected vs presented), the
  publication record, the worker identity row.
- **Recover:** the worker re-registers with a fresh incarnation;
  no data repair needed (the fence held).
- **Regression:** the F029/F031 fence suites already gate; add the
  new ordering if the violation found a hole.

## orphan-process-or-resource

- **Detect:** G002 obligation leak report / G015 dashboard; worker
  reap sweep finds unowned process groups or temp dirs.
- **Contain:** automatic — kill the process group; reap the temp
  tree under the crash-cleanup policy.
- **Operate:** `rch inspect operation OP-ID`; review the crashpack.
- **Evidence:** the G011 crash scene, obligation table snapshot,
  process/resource inventory.
- **Recover:** verify the reap; if obligations leaked, the G-series
  supervision bug is the incident, not the orphan.
- **Regression:** a cancellation-at-that-await fixture (G012 lab).

## protocol-compatibility-failure

- **Detect:** J002 negotiation refusals spiking, or the R009 doctor
  flagging skew.
- **Contain:** automatic — refused sessions stay refused (fail
  closed); no downgrade.
- **Operate:** `rch doctor --fleet`; follow its remediation lines.
- **Evidence:** both hellos, the doctor report, deploy timeline.
- **Recover:** upgrade the older side per the doctor; verify with a
  fresh doctor run.
- **Regression:** T009 upgrade-matrix case for the failing pair.

## worker-identity-mismatch

- **Detect:** S001 identity store mismatch: presented identity does
  not match the pinned worker key.
- **Contain:** automatic — the connection refuses; the worker is
  excluded from scheduling (I008 hard exclusion).
- **Operate:** `rch inspect worker WORKER-ID`; audit the identity
  store rotation log.
- **Evidence:** presented vs pinned identity, rotation history,
  connection metadata.
- **Recover:** if legitimate rotation: re-pin through the S001
  rotation path. If not: treat as compromise; rotate fleet secrets.
- **Regression:** identity-mismatch fixture on the handshake path.

## secret-exposure

- **Detect:** S007 nonshareable classification firing on an artifact
  that already left the box, or plaintext found in a
  transcript/receipt audit.
- **Contain:** automatic — the artifact's namespace is marked
  nonshareable and pulled from serving; the S003 tokens for the
  affected slot are revoked immediately.
- **Operate:** rotate the exposed secret at its source FIRST; then
  `rch inspect object` the exposure path.
- **Evidence:** the redaction outcome, the artifact identity, the
  slot name (never the value), the delivery audit trail.
- **Recover:** rotated secret + re-run of affected actions under the
  new slot version; confirm the old value is dead at the source.
- **Regression:** a planted-secret fixture through the exact leak
  path (S007's suite extends).

## storage-exhaustion

- **Detect:** S008 disk/temp quota refusals; store write failures.
- **Contain:** automatic — per-peer quotas already bound the blast
  radius; retention (P008/H-series) evicts by policy.
- **Operate:** `rch inspect cache`; review retention policy sizing.
- **Evidence:** quota counters, largest-namespace table, eviction
  log.
- **Recover:** raise quota or tighten retention; verify headroom.
- **Regression:** quota-exhaustion fixture stays bounded (S008).

## scheduler-pressure-collapse

- **Detect:** I006 pressure signals + I012 brownout engaging;
  admission refusals spiking.
- **Contain:** automatic — brownout sheds speculative load first
  (I012); hard exclusions protect collapsing workers (I008).
- **Operate:** `rch why slow BUILD-ID`; review I014 storm telemetry.
- **Evidence:** pressure receipts, brownout decisions, queue depths.
- **Recover:** capacity returns → brownout lifts by its own
  hysteresis; review pool sizing (I013/I017).
- **Regression:** an I014 storm scenario at the collapse shape.

## cancellation-hang

- **Detect:** a cancel acknowledged but the operation still holds
  obligations after its deadline (G002/G010 supervision).
- **Contain:** automatic — escalate kill to the process group;
  fence the attempt (F031) so late output is dead.
- **Operate:** `rch inspect operation OP-ID`; pull the crashpack.
- **Evidence:** the cancellation timeline (sequence-stamped), the
  await-point inventory, the crash scene.
- **Recover:** kill + reap verified; the hang's await point gets a
  G012 lab case.
- **Regression:** cancellation-at-every-await must cover the point.

## reconciliation-conflict

- **Detect:** I52 sequence-domain reconciliation finds two
  irreconcilable authoritative records for one identity.
- **Contain:** automatic — both records preserved; the identity is
  quarantined from serving (never pick a winner silently — the
  T044/H003 posture).
- **Operate:** `rch inspect action KEY`; compare publication
  records.
- **Evidence:** both records, their sequence provenance, the
  authority matrix rows in force.
- **Recover:** the A005 authority rules decide; if they cannot, the
  identity stays quarantined and the bug is in authority handling.
- **Regression:** a T040-family scenario reproducing the ordering.

## key-instability-regression

- **Detect:** Q011/F018 fragmentation spike on one component, or
  F014 invariance failures: identical inputs producing different
  keys.
- **Contain:** automatic — affected families demote to the
  path-preserving/local lane (D030) until stable.
- **Operate:** `rch why miss` on sampled misses; read the component
  histogram.
- **Evidence:** breakdown diffs, the fragmenting component's
  histogram, recent key-code changes.
- **Recover:** fix the unstable component; F014/F015 must pass;
  epoch-bump if persisted keys are poisoned.
- **Regression:** an F014 invariance case for the unstable input.

## hit-rate-fragmentation

- **Detect:** hit rate sags while Q011 shows variant spread rising.
- **Contain:** none automatic — this is an efficiency incident, not
  a correctness one; serving stays sound.
- **Operate:** run the Q011 analyzer; apply its costed convergence
  recommendations (R010 dashboard).
- **Evidence:** the analyzer report, per-category waste, the
  convergence deltas over time.
- **Recover:** converge the top fragmenter; re-measure.
- **Regression:** the fleet corpus report tracks the category —
  regression shows up as the waste number climbing back.

---

# RABS Section 173 Required Documentation Set (bead R013)

- **Governed Schema Fingerprint:** `0x1a61e5bd8ad2cfb5`
- **Evidence Vocabulary:** `OBSERVED` | `VERIFIED` | `PARTIAL` | `REPORTED` | `TARGET` | `HYPOTHESIS` | `OPEN` | `BLOCKED` | `DEFERRED` | `REJECTED`

## doc-01-architecture-overview

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.local-wrapper@1`, `rabs.application@1`, `atp.transport@0`
- **Profile Boundary:** Single-trust-domain fleet (local wrapper, local edge daemon `rabsd`, coordinator, remote workers `rabs-wkr`).
- **Non-Claim Boundary:** `DEFERRED` cross-organization untrusted multi-tenant federation; `NON-CLAIM` zero-overhead local builds when daemon is unreachable (fail-open bounded to `<5ms`).
- **Operator Surfaces:** `rch rabs status`, `rch rabs doctor`, `rch why`

## doc-02-action-key-contract

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.action-key@1`, `rabs.action-family-key@1`, `rabs.action-key-breakdown@1`, `rabs.dependency-projection@1`, `rabs.observed-input-recipe@1`
- **Profile Boundary:** SHA-256 domain-separated (`rabs.action-key.sha256.v1`) canonical descriptors over byte-exact inputs, rustc compiler identity, and `v1` exact-artifact dependency projection.
- **Non-Claim Boundary:** `REJECTED` path-sensitive raw host strings in portable keys; `OPEN` semantic export-surface `.rmeta` projection until corpus equivalence gates pass.
- **Operator Surfaces:** `rch why action`, `rch why miss`, `rch rabs action show`

## doc-03-canonical-execroot-contract

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.build-path-semantic-policy@1`
- **Profile Boundary:** Canonical `/rabs/execroot/{work,out,deps,sysroot,tmp}` layout on Linux user/mount namespaces with deterministic `-ffile-prefix-map` / `--remap-path-prefix`.
- **Non-Claim Boundary:** `PARTIAL` macOS host-sandbox path-remapped fallback when Linux namespace isolation is unavailable; `NON-CLAIM` bit-identical paths for `SubscriberPathPreserving` local lanes.
- **Operator Surfaces:** `rch rabs doctor`, `rch why volatile`, `incident_bundle`

## doc-04-sandbox-policy-matrix

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.sandbox-semantic-policy@1`, `rabs.isolation-profile@1`, `rabs.source-capture-policy@1`
- **Profile Boundary:** Per-`ActionClass` hermetic sandbox enforcement (`StrictHermeticLinux`, `StrictHermeticVm`, `HostSandboxAudit`, `DependencyImmutableFastPath`, `VolatileLocal`) with network disabled by default and `.gitignore` never treated as a security boundary.
- **Non-Claim Boundary:** `BLOCKED` serving from `VolatileLocal` or `HostSandboxAudit` without matching trust policy; `NON-CLAIM` kernel-level containment on unprivileged non-Linux hosts without VM helper.
- **Operator Surfaces:** `rch rabs doctor`, `rch why action`, `incident_bundle`

## doc-05-rabs-atp-protocol-specification

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.local-wrapper@1`, `rabs.application@1`, `atp.transport@0`, `rabs.reason-codes@1`
- **Profile Boundary:** Length-framed canonical codecs, explicit `ATP/0` transport and `RABS/1` application negotiation, 0-RTT idempotent-only replay guard, and dedicated control-reserve / saturation latency gate.
- **Non-Claim Boundary:** `REJECTED` implicit protocol downgrade or unauthenticated 0-RTT state mutation; `HYPOTHESIS` cross-WAN congestion superiority before shadow soak completion.
- **Operator Surfaces:** `rch rabs protocol compatibility`, `rch rabs doctor`, `incident_bundle`

## doc-06-object-cas-format-and-gc-policy

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.object-manifest@1`, `rabs.artifact-bundle@1`, `rabs.chunking-profile@1`, `rabs.pack-format@1`, `rabs.metadata-store@1`
- **Profile Boundary:** Acyclic bounded tree manifests, content-defined chunking, deterministic small-object packs, two-phase `PreparedResultOffered` -> `ActionResultCommitted` publication, and pin/lease-respecting GC watermark sweeps.
- **Non-Claim Boundary:** `NON-CLAIM` serving unverified or partially closed blobs; `REPORTED` pack compaction ratios depend on workload crate graph shape.
- **Operator Surfaces:** `rch rabs object stat`, `rch rabs gc plan`, `rch rabs quarantine list`

## doc-07-cancellation-and-obligation-contract

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.metadata-store@1`, `rabs.local-wrapper@1`
- **Profile Boundary:** Reference-counted subscriber interests, quiescent last-subscriber drain, process-group/cgroup kill escalation (`SIGTERM` -> `SIGKILL`), and zero leaked obligations across every await point.
- **Non-Claim Boundary:** `NON-CLAIM` instant teardown of unkillable kernel D-state I/O; `VERIFIED` attempt fencing ensures late outputs after cancellation are tombstoned.
- **Operator Surfaces:** `rch rabs operation show`, `rch rabs worker reconcile`, `incident_bundle`

## doc-08-trust-provenance-policy

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.metadata-store@1`, `rabs.artifact-bundle@1`
- **Companion Document:** `docs/rabs-trust-model-v1.md`
- **Profile Boundary:** Single administrative trust domain (V1), Ed25519 worker identity pinning, `Tier0`–`Tier5` trust evidence tiers, and non-shareable secret-tainted output quarantine.
- **Non-Claim Boundary:** `DEFERRED` cross-domain peer cache sharing; `REJECTED` promotion of `Tier0`/`Tier1` records into shared remote serving without re-execution.
- **Operator Surfaces:** `rch rabs quarantine inspect`, `rch why action`, `incident_bundle`

## doc-09-worker-admission-policy

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.isolation-profile@1`, `rabs.application@1`
- **Profile Boundary:** Cryptographic identity handshake, toolchain digest equivalence, target-CPU/microarchitecture feature guard, PSI/disk headroom admission, and monotonic `WorkerBootGeneration` / `WorkerIncarnationId` fencing.
- **Non-Claim Boundary:** `NON-CLAIM` scheduling onto workers with drifted schema fingerprints or unprobed sandbox capabilities.
- **Operator Surfaces:** `rch rabs doctor`, `rch why worker`, `rch rabs worker reconcile`

## doc-10-wrapper-cargo-compatibility-matrix

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.local-wrapper@1`, `rabs.invocation-record@1`
- **Companion Document:** `docs/rabs-canonical-cargo.md`
- **Profile Boundary:** `RUSTC_WRAPPER` / `RUSTC_WORKSPACE_WRAPPER` interception, Cargo JSON diagnostic + early `.rmeta` pipelining notification, jobserver token hygiene, and `cargo check`/`build`/`test`/`clippy`/`nextest` classification.
- **Non-Claim Boundary:** `PARTIAL` proc-macro host dylib cross-compilation caching; `BYPASSED` interactive/watch invocations execute locally by design.
- **Operator Surfaces:** `rch rabs doctor`, `rch why miss`, `rch why rebuild`

## doc-11-rollout-and-rollback-guide

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.application@1`, `rabs.metadata-store@1`
- **Profile Boundary:** 14 independently scoped feature modes (`off` through `require-remote`), canary coordinator/worker cohort routing low-risk `RustcDependencyCompile` actions first, and one-command rollback (`execute_one_command_rollback`).
- **Non-Claim Boundary:** `REJECTED` rollback past the coordinator's N-1 protocol compatibility floor without draining in-flight work.
- **Operator Surfaces:** `rch rabs mode`, `rch rabs shadow-report`, `rch rabs status`

## doc-12-incident-runbooks

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.reason-codes@1`, `rabs.metadata-store@1`
- **Companion Document:** `docs/rabs-incident-runbooks.md`
- **Profile Boundary:** All 13 incident classes (`IncorrectResultDivergence` through `HitRateFragmentation`) with detection signal, automatic containment, operator commands, redaction-safe evidence bundle, recovery path, and regression-test closure gate.
- **Non-Claim Boundary:** `NON-CLAIM` automatic containment for `HitRateFragmentation` (efficiency incident only; serving remains sound).
- **Operator Surfaces:** `incident_bundle`, `rch rabs quarantine list`, `rch why`

## doc-13-benchmark-methodology

- **Standing:** `OBSERVED`
- **Schemas:** `rabs.invocation-record@1`, `rabs.reason-codes@1`
- **Companion Document:** `benchmarks/GATE_LEDGER.md`
- **Profile Boundary:** Nearest-rank p50/p95/p99 integer latency percentiles, warm/cold/noop/leaf-edit/branch-switch scenarios, served-fraction permille accounting (`>900` permille long-run target), and live incumbent vs candidate comparison in the same invocation.
- **Non-Claim Boundary:** `TARGET` `>90%` fleet `rustc` served fraction is `ReportedNotGated` until the Phase 5 / M16 frontier review; self-speedups are maintenance, never release wins.
- **Operator Surfaces:** `rch rabs benchmark replay`, `rch rabs shadow-report`, `rch why slow`

## doc-14-agent-command-palette

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.reason-codes@1`, `rabs.action-key-breakdown@1`
- **Profile Boundary:** Bounded JSON/TOON machine-readable outputs on stdout with diagnostics on stderr across `rch why {action,crate,miss,rebuild,worker,volatile,slow}` and `rch rabs {status,doctor,mode,replay,shadow-report,action,operation,object,quarantine,gc,worker,cache,advise,benchmark,protocol}`.
- **Non-Claim Boundary:** `NON-CLAIM` unredacted environment/secret values in agent-visible JSON or TOON payloads.
- **Operator Surfaces:** `rch why`, `rch rabs status`, `rch rabs advise`

## doc-15-developer-contribution-guide

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.action-key@1`, `rabs.local-wrapper@1`, `rabs.application@1`, `rabs.metadata-store@1`, `rabs.object-manifest@1`, `rabs.sandbox-semantic-policy@1`
- **Profile Boundary:** Crate dependency-direction DAG (`rabs-protocol` leaf without Tokio/Asupersync/FS effects), `#![forbid(unsafe_code)]`, cold-namespace schema epoch bumps, and mandatory coverage-ledger + documentation currency checks in CI.
- **Non-Claim Boundary:** `REJECTED` compatibility shims, unversioned wire changes, or schema registry edits without matching documentation updates.
- **Operator Surfaces:** `rch rabs doctor`, `rch rabs protocol compatibility`

## doc-16-unsafe-boundary-ledger-and-review-guide

- **Standing:** `VERIFIED`
- **Schemas:** `rabs.sandbox-semantic-policy@1`, `rabs.isolation-profile@1`
- **Companion Document:** `docs/rabs-unsafe-boundary-ledger.md`
- **Profile Boundary:** Zero inline `unsafe` in RABS libraries; every privilege/namespace/seccomp/tracing boundary is isolated to audited helper binaries tracked with 6 required facets in `docs/rabs-unsafe-boundary-ledger.md`.
- **Non-Claim Boundary:** `BLOCKED` shipping any privileged helper binary whose path is absent from `docs/rabs-unsafe-boundary-ledger.md` or lacks fuzz/review metadata.
- **Operator Surfaces:** `rch rabs doctor`, `incident_bundle`

