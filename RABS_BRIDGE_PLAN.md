# RABS Bridge Plan — From Proven Library to Living System

> Companion to `COMPREHENSIVE_MASTER_PLAN_FOR_RABS_ASUPERSYNC_NATIVE.md`.
> That document is the vision; THIS document is the gap-closure execution
> plan produced by the 2026-08-10 reality check. Finding: 261/513 beads
> closed, the M1 keystone live-proven, ~92K LOC of tested domain logic —
> and zero end-to-end capability, because no process boots RABS. The
> dominant gap is the SPINE. This plan closes every identified gap, spine
> first, then converts each library into delivered capability one served
> class at a time, with the plan's §6 targets wired as enforcing gates as
> each becomes measurable. Revised in place; never forked.

## Governing principles

1. **Spine before flesh.** Nothing new goes into pure-library form if its
   consumer process doesn't exist yet; the walking skeleton comes first
   and every subsequent phase lands INSIDE it.
2. **Shadow before authority.** Every serving class runs in shadow
   (observe + would-have-hit + divergence-compare) against real
   production traffic from the corpus recorder before it may serve a
   byte. The 0-divergence sentinel is live from the first shadow day.
3. **Refuse, never fake.** Skeleton stubs are typed refusals with
   reasons, not mocks that pretend success (honest-work law).
4. **Pay the re-integration tax explicitly.** Every epic closed at
   library fidelity (F, H, O, C, large parts of D) gets a named
   live-integration bead re-verifying its acceptance UNDER THE RUNNING
   SPINE. A unit-proven module is not done until a process exercises it.
5. **Gates land with capabilities.** Each §6 quantitative target gets an
   enforcing CI/corpus gate in the same phase that makes it measurable —
   never deferred to a final "measurement" phase.
6. **T-epic runs vertical, not terminal.** Every phase ships its own
   fuzz/chaos/soak beads; the proof program is a lane, not a finale.

---

## Phase S — The Walking Skeleton (unblocks everything; ~2 weeks of beads)

Goal: `rabsd` boots, a real wrapper talks to it, a worker session exists,
and shadow mode runs against production RCH traffic — with every decision
flowing through the REAL modules already built (breaker, handshake,
action keys, leases, T053 logs, decision receipts).

- **S1. `rabsd` binary + Asupersync runtime island.** `src/main.rs`:
  config load (reuse RCH config conventions), boot the region tree from
  `rabs-asupersync` with REAL asupersync runtime integration (today those
  are models only — this is the M2 keystone), structured T053-format
  logging, panic=abort with crashpack capture, clean shutdown that drains
  obligations. Acceptance: `rabsd --help`, boot/shutdown under 100ms,
  obligation-clean exit proven by log inspection, kill -9 recovery test.
- **S2. Tiny wrapper binary (`rabs-wrap`).** Real `RUSTC_WRAPPER` entry:
  breaker state read → UDS connect → C001 handshake → decision → local
  passthrough exec (shadow mode always passes through). Release-profile
  binary per A021. Acceptance: C010 gate RERUN against this real binary
  end-to-end (not the noop proxy), p95 < 10ms on csd and hz2; wrapper
  contract matrix (C009) green with the wrapper interposed on all three
  channels.
- **S3. UDS server in the edge.** Listener at the configured socket,
  socket-admission (existing module) enforced, version negotiation
  (existing module) live, per-connection T053-trace. Acceptance: storm
  test — 64 concurrent wrapper connects, zero drops, admission refusals
  typed.
- **S4. Shadow decision plane.** For every wrapper consult: compute the
  REAL action key (Epic F pipeline) from the REAL captured invocation
  (B001 recorder schema), record would-have-hit/miss + reason into the
  decision-receipt store (R epic), compare replayed outcomes (B005) for
  divergence. Acceptance: 24h of production multi-agent traffic on csd
  with shadow reports produced and ZERO behavioral change to builds
  (checksum-compare a sample of artifacts built with/without wrapper).
- **S5. `rabs-wkr` binary skeleton.** ATP worker session (integrate the
  real `asupersync`/`atp` crates — the protocol schemas in rabs-protocol
  finally get a wire), capability + pressure report (reuse probe logic),
  canonical-namespace execution service wrapping the PROVEN rabs-sandbox
  launcher, prepared-result offer type flowing (refused by coord until
  M4). Acceptance: session established csd↔hz2 over ATP, capability
  report visible in `rabsd` status, one remote canonical execution round
  trip (the D003 acceptance, but ORCHESTRATED, not hand-SSH'd).
- **S6. Coordinator role boots in-process.** The coord module gets its
  loop: lease registry (D024) and destination arbiter (D031) mounted
  live, singleflight table live. Acceptance: two concurrent shadow
  consults for the same action key produce one leader + one follower in
  the receipts.
- **S7. Packaging + fleet provisioning (NO_BEAD gap, now beaded).**
  `rabs-wrap`/`rabsd`/`rabs-wkr` in the release build, install.sh flag,
  `rch fleet deploy`-style rollout for rabs-wkr to the bwrap-capable
  workers, systemd/launchd units, `rabs doctor`. Acceptance: one-command
  deploy to hz2 + one vmi from a clean state.
- **S8. Spine chaos starter (T-lane).** Kill/restart each process mid-
  shadow-consult; breaker opens/closes per C-epic state machine; no
  wedged wrappers (fail-open verified under fault injection).

## Phase 1 — First Served Class: registry/git dep compiles (M4)

The smallest real value with the largest denominator: registry dep
rlib/rmeta compiles are path-canonical (PROVEN), immutable-input,
highest-repetition. Serve them across worktrees from the CAS.

- Live-integrate rabs-cas as the on-disk store under `rabsd` (re-
  integration bead: its library acceptance re-run through the daemon).
- Worker executes dep compiles inside the canonical namespace (D005
  mounts, D006 unit mappings — all proven); harvest via K-epic beads;
  publish via H-epic pin/commit machinery (library-closed → live bead).
- Edge materializes hits: D009 dep-info derivation + D010 mtime
  choreography + D031 arbiter + D025 replacement semantics — all
  library-proven, all getting their live beads here.
- **Divergence sentinel live**: every served result shadow-compared
  against a real local execution for a configurable sample rate
  (start 100%, ratchet down on evidence). Target: 0, enforced.
- Gate (from §6): local small-artifact hit < 50ms + fs cost; miss
  overhead < 2% on admitted actions; measured on the replay corpus and
  stored next to the B015 baselines.
- Milestone acceptance (M4): two-worktree demo — worktree B's cargo
  build gets its registry deps SERVED, wall-clock delta recorded,
  divergence 0, `rch why` explains every serve decision.

## Phase 2 — Authority, Fleet, Data Plane (M6–M8)

- Coordinator authoritative commits (I5/I10 machinery from G/H epics
  goes live; workers offer, never commit — R50 enforced on the wire).
- ATP object data plane: chunked CAS transfer, resumable, digest-
  verified (J/K beads); fleet singleflight across ≥3 workers.
- Scheduler + jobserver (Epic I): root-permit broker live under real
  concurrent Cargo storms; 15-agent storm benchmark harness built (T)
  and baselined against current-RCH numbers (B009 completes here).
- Multi-machine convergence re-proof: D019's cross-machine digest
  equality re-run CONTINUOUSLY as a fleet health check.

## Phase 3 — Workspace Plane + Whole-Command (M9–M10)

- Whole-command canonical remote execution over ATP (the current-RCH
  replacement path) with target-state leases (D024) live.
- Workspace-member rustc actions served (Epic M): the D018/D032
  snapshot/lineage machinery live per command; M002 canonical snapshots.
- Gate: median agent edit/check/test loop ≥3× on the replay corpus —
  the headline §6 number, now measurable honestly.

## Phase 4 — The Long Tail of Value (M11–M14)

- Build-script run cache (Epic N — currently 0%): D025 replacement
  semantics live, hermeticity classes from E-epic discovery.
- Test-result cache (O mostly closed → live beads), link acceleration
  (L), incremental snapshots/time travel (P, evidence-gated), then
  speculation/prewarm (Q) driven by the edit-watcher.
- Each class follows the same ladder: shadow → sampled divergence →
  authority, with its own T-lane chaos beads.

## Phase 5 — Ops, Advise, Frontier (M15–M16)

- `rch advise`/fragmentation analyzer, N-epic diagnostics surface (0%
  today — but its consumers only exist after Phases 1–3), R-epic
  operations polish, S-epic macOS lanes (D013/D021 land here where VM
  infra exists), evidence-gated frontier review against ALL §6 gates.

## Cross-cutting workstreams (run alongside every phase)

- **W1 Re-integration ledger.** One bead per library-closed epic
  chapter, auto-created at the phase that mounts it; a closed library
  bead plus its live bead together are the real "done".
- **W2 Gate ledger.** §6 table → one enforcing gate each, landing per
  the phase map above; a gate that cannot yet run is listed as PENDING
  with its unlock phase, never silently absent.
- **W3 T-epic verticalization.** Existing 44 open T-beads get phase
  labels; each phase's exit requires its T-slice green, including the
  E023/T018 fuzz debt from Epic D.
- **W4 Honesty instrumentation.** T053 logging + decision receipts wired
  through every new process from day one; `rch why` answers from real
  receipts starting in Phase S shadow mode.
- **W5 Corpus flywheel.** The B001 production recorder keeps feeding the
  replay corpus; every phase's claims are measured against it, next to
  the B015/B009 baselines (sccache: cached cold build 54.5s workspace /
  32.9s asupersync — the numbers to beat are already on record).

## Sequencing summary

S is strictly first and internally mostly parallelizable (S1‖S2‖S5, then
S3→S4→S6, S7/S8 trailing). Phase 1 needs S complete. Phases 2–5 follow
the milestone DAG already encoded in the beads. The 250 open beads map
onto this plan; the NET-NEW beads this plan demands are: the eight S-beads
(spine + packaging, closing the NO_BEAD gap), the W1 re-integration
ledger (~10 beads), the W2 gate ledger (~10 beads), and phase labels on
the T backlog. Everything else already exists in the graph and gains
only sequencing.
