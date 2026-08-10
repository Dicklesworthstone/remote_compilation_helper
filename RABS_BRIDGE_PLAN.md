# RABS Bridge Plan — From Proven Library to Living System

> Companion to `COMPREHENSIVE_MASTER_PLAN_FOR_RABS_ASUPERSYNC_NATIVE.md`.
> That document is the vision; THIS one is the gap-closure execution plan
> from the 2026-08-10 reality check. Finding: 261/513 beads closed, the
> M1 keystone live-proven on the fleet, ~92K LOC of tested domain logic —
> and zero end-to-end capability, because no process boots RABS. The
> dominant gap is the SPINE. This plan closes every identified gap, spine
> first, then converts each library into delivered capability one served
> class at a time, with §6 targets wired as enforcing gates the moment
> each becomes measurable. Revised in place; never forked.

## Governing principles

1. **Spine before flesh.** No new pure-library modules whose consumer
   process doesn't exist. The walking skeleton lands first; everything
   after lands INSIDE it.
2. **Shadow before authority.** Every serving class runs in shadow
   (observe + would-have-hit + divergence-compare against real local
   execution) on real production traffic before serving a byte. The
   0-divergence sentinel is live from the first shadow day.
3. **Refuse, never fake.** Skeleton stubs are typed refusals with reason
   codes, not mocks that pretend success.
4. **Pay the re-integration tax explicitly.** Every epic closed at
   library fidelity gets a named live-integration bead re-verifying its
   original acceptance UNDER THE RUNNING SPINE. Library-done + live-done
   together are the only real "done".
5. **Gates land with capabilities.** Each §6 target gets an enforcing
   gate in the same phase that makes it measurable. A gate that cannot
   yet run is listed PENDING with its unlock phase — never silently
   absent.
6. **T-epic runs vertical.** Every phase exits only with its own
   fuzz/chaos/soak slice green; the proof program is a lane, not a
   finale.
7. **One mechanism, no drift.** Wherever a live path exists (D003 argv
   builder, D024 leases, D031 arbiter, B001 recorder), the spine mounts
   THAT module — a spine that reimplements a proven library is a defect.

---

## Phase S — The Walking Skeleton

Everything else in this plan is blocked behind S. Internal order:
S1‖S2‖S5 in parallel → S3 → S4 → S6 → S7 → S8. Estimated grain: 8 beads,
each 0.5–2 sessions.

### S1. `rabsd` binary + real Asupersync runtime island (THE M2 keystone)

`rabsd/src/main.rs`. Work items, in order:

1. **Runtime boot**: instantiate the actual `asupersync` runtime (the
   pinned rev is already a dependency with a curated feature profile —
   bead A004 — and ZERO call sites today). Root region = daemon
   lifetime; child regions per plan §12: `edge`, `coord`, `telemetry`,
   `janitor`. Map the existing `rabs_asupersync::region_tree` MODEL onto
   real regions: the model becomes the introspection/assertion layer
   over the live tree (the model is the spec; the runtime is the
   implementation; a divergence between them is a boot-time panic).
2. **Obligation-clean shutdown**: SIGTERM → region-cancel cascade →
   every obligation in `rabs_asupersync::obligations` either fulfilled
   or explicitly abandoned-with-reason in the shutdown receipt. Kill -9
   recovery: next boot replays the crashpack (existing module) and
   reports orphaned state.
3. **Config**: reuse RCH's config precedence chain; `[rabs]` section in
   the existing config.toml; `RABS_*` env overrides; refuse-on-unknown-
   key (config drift = typed error, not silent ignore).
4. **T053 logging from process birth**: every region gets a trace ID at
   spawn; the daemon's own lifecycle emits the standard's records.

Acceptance: (a) `rabsd --version/--help/--check-config` under 10ms;
(b) boot-to-ready and SIGTERM-to-exit each under 100ms on csd and hz2;
(c) shutdown receipt shows zero unaccounted obligations across 100
boot/kill cycles (scripted); (d) kill -9 mid-work → next boot crashpack
names the orphaned region; (e) model-vs-runtime region-tree assertion
active in debug builds.

### S2. Tiny wrapper binary `rabs-wrap` (real RUSTC_WRAPPER)

New minimal crate (A021's split-profile work applies: `opt-level="z"`,
LTO, panic=abort, stripped). Decision path per invocation:

1. argv[1..] classification (rustc vs probe — reuse the D019/C009
   parser knowledge: `-vV`/`___` probes always pass through instantly);
2. breaker-state file read → `wrapper_breaker::decide` (existing);
3. Closed-breaker path: UDS connect with the C-epic connect budget →
   C001 handshake (existing schema) → send B001-shaped invocation
   summary → receive decision (shadow mode: always `PassThrough`);
4. exec the real rustc, preserving EVERYTHING (exit code, signals,
   stdio streaming — no buffering, C007);
5. breaker-state update via `on_outcome` (existing).

Acceptance: (a) C010 overhead gate RE-RUN measuring THIS binary
end-to-end against a live rabsd — replaces the noop proxy; p95 < 10ms
enforced release-profile on csd and hz2, recorded beside the existing
numbers; (b) C009 contract matrix re-run with `rabs-wrap` interposed on
stable/beta/nightly — byte-identical build results, fixtures unchanged;
(c) daemon-dead test: rabsd stopped → wrapper passes through within the
breaker budget, breaker opens after the configured failures, probe
cadence honored (existing state machine, now live); (d) `#![forbid
(unsafe_code)]`, release binary < 2 MiB.

### S3. UDS server in the edge region

Inside S1's `edge` region: listener at the configured socket path,
`socket_admission` (existing module) enforced per connection,
`version_negotiation` (existing) on every handshake, per-connection
child region so a hung connection cancels cleanly, T053 trace per
consult.

Acceptance: (a) 64-way concurrent wrapper storm: zero drops, zero
wedges, admission refusals typed; (b) malformed-frame fuzz (reuse
protocol fuzz corpus) against the LIVE socket — no panic, typed
refusals; (c) socket file permissions 0600; stale-socket takeover safe
(flock + liveness probe, not blind unlink).

### S4. Shadow decision plane (M0's "shadow-only" promise, delivered)

For every wrapper consult, in the edge region:

1. Reconstruct the invocation via the B001 recorder schema (same code
   path as the production corpus recorder — one schema, two consumers);
2. Compute the REAL action key through the Epic F pipeline;
3. Look up would-have-hit against the shadow index (starts empty;
   populated by shadow-observed completions — the F-epic discovery
   cycle live);
4. Emit a decision receipt (R-epic schema) with outcome
   `ShadowPassThrough{would_have_hit, reason}`;
5. Nightly (or on-demand) shadow report: hit-rate by action class,
   would-have-saved estimates against B015/B009 baselines, divergence
   candidates queued for B005 replay comparison.

Acceptance: (a) 24h of real multi-agent traffic on csd with the wrapper
installed for at least one project: zero build breakage, zero artifact
divergence on a 50-build checksum sample (built with vs without wrapper
interposed); (b) shadow report generated with per-class hit rates;
(c) added latency accounted: consult p95 within the C010 budget under
real load; (d) receipts complete: every consult has exactly one receipt
(count reconciliation vs the corpus recorder's NDJSON).

### S5. `rabs-wkr` skeleton: real ATP session + orchestrated canonical exec

1. Worker main: boot runtime (same S1 machinery, worker region layout);
   establish authenticated ATP session to the coordinator (integrate the
   real `asupersync`/ATP transport — first wire use of the J-epic
   schemas); heartbeat with capability + pressure report (reuse
   HostIsolationSupport probe + disk/load sampling);
2. Execution service: accept a `CanonicalExecRequest` (namespace spec +
   argv, J-epic schema), run it through the PROVEN rabs-sandbox
   launcher, stream stdout/stderr/exit back, offer outputs as
   prepared-result metadata (H-epic pin schema) — coordinator refuses
   commits until Phase 1 (typed refusal, exercised in tests).

Acceptance: (a) session csd↔hz2 over ATP with capability visible in
`rabsd` status output; (b) THE ORCHESTRATION PROOF: the D003/D005
acceptance suite executed remotely via the session — same assertions
that were hand-SSH'd during Epic D, now flowing through the real
control plane; (c) session survives network flap (ATP resume) and
worker restart (session re-establish + capability re-report);
(d) worker never sees a commit API (compile-time: the worker crate
imports no commit types — R50 structurally).

### S6. Coordinator role boots in-process

The `coord` region gets its loop: mount D024 `TargetLeaseRegistry`,
D031 `DestinationArbiter`, and a singleflight table keyed by action key.
Edge consults route through coord in-process (plan §10: one binary,
authority split structural).

Acceptance: (a) two concurrent shadow consults for one action key →
receipts show one leader + one follower; (b) lease/arbiter state
inspectable via `rabsd status --coord`; (c) coord region restart (fault
injection) does not take down edge consults (typed degraded mode,
breaker semantics per C-epic).

### S7. Packaging + fleet provisioning (the NO_BEAD gap, closed)

Release builds of `rabs-wrap`/`rabsd`/`rabs-wkr` in CI; install.sh
`--with-rabs` flag; `rch fleet deploy`-pattern rollout for rabs-wkr to
bwrap-capable workers (capability-gated: refuses non-bwrap hosts with
the reason); launchd (csd) / systemd (workers) units; `rabsd doctor`
covering socket, breaker file, worker sessions, CAS dir.

Acceptance: one-command deploy to hz2 + one vmi from clean state;
doctor green; uninstall leaves no live hooks (breaker file quiesced so
wrappers pass through permanently).

### S8. Spine chaos slice (T-lane for Phase S)

Fault-injection suite: kill each process at randomized points mid-
consult/mid-exec (seeded, T053-logged); assert fail-open invariants —
no wedged wrapper > budget, no lost receipt without a crashpack entry,
breaker state machine transitions exactly per the C-epic model under
real faults. Soak: 24h shadow mode under production agent load with
zero unexplained receipt gaps.

---

## Phase 1 — First served class: registry/git dep compiles (M4)

Smallest real value, largest denominator, lowest risk: registry/git dep
compiles are immutable-input, path-canonical (PROVEN), and dominate
cold/branch-switch builds. Ladder within the phase:

1. **Live CAS**: mount rabs-cas as the on-disk store under rabsd
   (re-integration bead: the library's atomic-publication acceptance
   re-run through daemon crash-kill cycles); quota + janitor region.
2. **Worker dep-compile execution**: coordinator plans the canonical
   namespace for a registry unit (D005 mounts + D006 mappings — proven),
   worker executes, harvests via K-epic beads, offers; coordinator
   commits under H-epic pins (the library machinery's first live
   commits).
3. **Edge materialization**: D009 dep-info derivation + D010 mtime
   choreography + D028 byte-correct derivation + D031 arbiter + D025
   replacement — every one library-proven, every one getting its live
   bead here.
4. **Serving ladder per class, with PRINCIPLED ratcheting**: shadow →
   serve-with-100%-divergence-sampling → staged reduction governed by a
   sequential probability ratio test (SPRT), not vibes: treat each
   sampled serve as a Bernoulli trial with H0 "divergence rate ≤ 1e-6"
   vs H1 "≥ 1e-4"; the sampling rate may step down (100% → 25% → 5% →
   1% floor) only when the accumulated log-likelihood ratio crosses the
   accept-H0 boundary at α=β=1e-3, and ANY observed divergence resets
   the class to 100% + quarantine review. This gives every ratchet step
   an explicit, auditable risk bound recorded in its receipt — the
   decision to trust is itself evidence-bearing. The floor never
   reaches 0.
5. **Divergence sentinel**: served result vs real local execution;
   ANY divergence = class-wide automatic demotion to shadow + incident
   receipt (H-epic quarantine machinery live) + the divergent pair
   preserved whole as a minimization corpus entry (T012 feedstock).

Gates landing in this phase (§6): local small-artifact hit < 50ms +
unavoidable fs cost; miss overhead < 2% on admitted actions; served-
result divergence = 0. All measured on the replay corpus + live sample,
stored beside B015/B009 baselines.

Milestone acceptance (M4): the two-worktree demo — worktree B's real
`cargo build` receives its registry deps SERVED from worktree A's
execution, wall-clock delta recorded honestly (including all overhead),
divergence 0 over ≥1000 served units, `rch why` explains every serve
from real receipts.

## Phase 2 — Authority, fleet, data plane (M6–M8)

- Coordinator authoritative commit machinery live (I5/I10; workers
  offer, never commit — R50 now enforced on the wire, tested by a
  malicious-worker fixture attempting a commit frame → typed protocol
  violation + session termination).
- ATP object data plane: chunked, resumable, digest-verified CAS
  transfer (J/K); cross-worker singleflight on ≥3 workers; hedged
  fetches for tail control.
- Scheduler + jobserver (Epic I) live: root-permit broker under real
  15-agent storms; the storm harness (T) built and baselined against
  current-RCH (completing B009's remaining arm as a side effect).
- Continuous convergence probe: D019's cross-machine digest equality as
  a scheduled fleet health check (a failing host is evidence of drift —
  auto-quarantine from serving, H-epic).

## Phase 3 — Whole-command + workspace plane (M9–M10)

- Whole-command canonical remote execution over ATP replaces the
  current-RCH SSH path for RABS-enrolled projects; D024 leases and D018
  snapshots live per command; D032 lineage sealing per resolution.
- Workspace-member rustc actions served (Epic M): M002 canonical
  snapshots + observed-input recipes; pipelined rmeta (early-metadata
  streaming from workers).
- Gate: median agent edit/check/test loop ≥3× and p90 ≥2× on the replay
  corpus — the headline numbers, measured honestly with the corpus
  flywheel.

## Phase 4 — The long tail (M11–M14)

Build-script run cache (Epic N — 0% today; D025 semantics live +
E-epic hermeticity classes), test-result cache (O live beads), link
acceleration (L), incremental snapshots/time travel (P, evidence-gated
per plan), speculation/prewarm (Q) fed by the edit-watcher. Each class
climbs the same serving ladder with its own T-lane slice.

## Phase 5 — Ops, advise, frontier (M15–M16)

`rch advise` + fragmentation analyzer, Epic N diagnostics surface,
R-epic ops polish, S-epic macOS lanes (D013/D021 land here where VM
infrastructure exists), and the evidence-gated frontier review: every
§6 gate green or explicitly waived with evidence.

---

## Cross-cutting workstreams

- **W1 Re-integration ledger.** Auto-rule: when a phase mounts a
  library-closed module, a live bead re-runs its ORIGINAL acceptance
  under the spine. Initial ledger: rabs-cas atomic publication (Ph1),
  H-epic pins/quarantine (Ph1/2), F-epic key pipeline (S4), C-epic
  breaker/handshake (S2/S3), I-epic broker (Ph2), D024/D031 (S6),
  D009/D010/D025/D028 (Ph1), R-epic receipts (S4).
- **W2 Gate ledger.** §6 table → enforcing gates: wrapper p95 (LIVE
  since C010, re-scoped in S2); hit latency + miss overhead + divergence
  (Ph1); storm throughput (Ph2); agent-loop ratios + branch ping-pong
  (Ph3); cold wide workspace (Ph2/3); served-fraction telemetry (Ph3+).
  Ledger doc lists status: ENFORCING / PENDING(phase) — never absent.
- **W3 T-epic verticalization.** The 44 open T-beads get phase labels;
  each phase's exit criteria include its T-slice. E023/T018 (Epic D fuzz
  debt) lands in Phase S/1 since its subject is already live.
- **W4 Honesty instrumentation.** T053 records + decision receipts wired
  through every process from birth; `rch why` answers from real receipts
  starting in shadow mode; refusal reason codes stable and documented.
- **W5 Corpus flywheel.** B001 production recorder keeps feeding replay;
  every phase's claims measured against the corpus next to B015/B009
  baselines (sccache cached cold build: 54.5s workspace / 32.9s
  asupersync — the numbers to beat are on record).

## The asupersync integration contract (S1/S5 exactness)

The runtime island is not "use a runtime somewhere" — it is a specific
contract, and naming it now prevents S1 from drifting into a Tokio-shaped
port:

- **Regions own lifetimes**: every daemon subsystem is a region whose
  drop cancels its children; there are no detached tasks anywhere (the
  no-orphans claim R90 rests on this + cgroup containment on workers).
- **Cx is the only capability channel**: spawn/timer/IO capabilities
  flow through the context parameter; a module that wants IO declares it
  in its signature. This is what makes S8's fault injection tractable —
  a lab Cx swaps in deterministic time and faulty IO without cfg tricks.
- **Obligations are typed completions**: the `rabs_asupersync::
  obligations` model maps 1:1 onto reserve/commit/abort of real
  completion tokens; the shutdown receipt is generated FROM the
  runtime's own accounting, and the model layer asserts equivalence in
  debug builds (spec-vs-implementation, mechanically held).
- **Upstream gap protocol**: any missing asupersync API discovered
  during S1/S5 becomes an issue in the asupersync repo + a pinned-rev
  bump bead here (A010's upgrade bot lane) — never a local fork, never
  a vendored patch.

## Risk register with kill-criteria

| Risk | Phase | Tripwire | Response |
|---|---|---|---|
| Asupersync integration reveals blocking upstream gaps | S1/S5 | any S1 acceptance unreachable without upstream change | pause S-work on that item only; file upstream; continue parallel S items (S is deliberately parallel) |
| Wrapper overhead regresses with a real daemon behind it | S2 | re-scoped C010 gate > 10ms p95 | breaker default flips to pass-through-always until fixed; shadow data still collected out-of-band via B001 recorder |
| Shadow mode perturbs production builds at all | S4 | any checksum mismatch in the 50-build sample | wrapper uninstalled by default; S4 acceptance blocks S6+ |
| Divergence > 0 in Phase 1 | Ph1 | sentinel fires | class demoted automatically; M4 gate blocked; divergent pair minimized (T012) before any re-promotion |
| Fleet too saturated for honest gates | any | gate variance > 30% run-to-run | gates run on a reserved quiet window (worker drained via existing rch drain), never on contended hosts; contended numbers recorded but marked non-gating |
| Re-integration tax exceeds estimates | Ph1+ | live bead reopens > 20% of a "closed" epic | reality-check re-run for that epic; its remaining closed beads get audit beads before further phases consume them |

## Definition of spine-complete (Phase S exit)

All eight S-acceptances green, PLUS: one continuous week of shadow mode
on csd with zero build perturbation and complete receipts; the
orchestrated D003/D005 proof green via ATP; `rabsd doctor` green on csd
+ hz2 + one vmi; C010/C009 gates re-scoped to the real binaries and
enforcing in CI. Only then does Phase 1 open.

## Sequencing and bead delta

S first (S1‖S2‖S5 → S3 → S4 → S6 → S7 → S8); Phase 1 after S; 2–5 follow
the existing milestone DAG. The 250 open beads map onto Phases 1–5 and
gain only sequencing. NET-NEW beads: 8 spine (S1–S8), ~8 W1 ledger,
~6 W2 gate ledger, 1 T-labeling task, plus milestone rewires (M2 ←
S1, M0-edge ← S3/S4). Everything else already exists in the graph.
