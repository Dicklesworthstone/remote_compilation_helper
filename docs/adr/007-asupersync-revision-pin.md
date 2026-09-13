# ADR 007: Exact Asupersync Revision Pin for RABS

**Status:** Accepted
**Date:** 2026-08-06
**Bead:** `rabs-root-4pidu.19.3` (A003)
**Related:** RABS master plan Part XXIX §208 (evidence pins); beads A004
(rabs-profile feature set), A009 (consumer-driven adapter contract tests),
A010 (upgrade bot/report)

## Context

RABS adopts Asupersync as its runtime/lifecycle substrate, adapted solely
through the `rabs-asupersync` crate (invariant I14: no Asupersync types in
stable wire/durable/CLI schemas). The master plan's behavioral claims about
Asupersync (regions, obligations, process groups, ATP objects/journals,
deterministic lab, QUIC blockers §44) were verified against one exact
revision. Risk R8 (Asupersync API churn leaking into RABS) makes floating
dependencies unacceptable: every pin advance must be a deliberate,
evidence-bearing event.

## Decision

Pin `asupersync` as a git dependency at the **plan-reviewed revision**:

```toml
asupersync = { git = "https://github.com/Dicklesworthstone/asupersync.git", rev = "62d398ea17519d7e80cbdb32e062d70647cd58a4" }
```

- Reviewed revision: `62d398ea17519d7e80cbdb32e062d70647cd58a4`
  (2026-08-06; the commit the six adversarial plan passes examined).
  At synthesis time, upstream `main` was `513aa04f…`, a direct child whose
  delta was characterized as formatting-only; upstream has since advanced
  further (`9c53f4d2e…` at pin time). **Behavioral claims remain pinned to
  the reviewed commit until CI revalidates a newer pin** — that is the
  plan's own rule, and we follow it literally rather than pinning whatever
  HEAD happens to be.
- Crate metadata at the pin: `asupersync 0.3.10`, license
  `LicenseRef-MIT-OpenAI-Anthropic-Rider` (consistent with the A016
  license-alignment work in this repo).
- The dependency lives in `rabs-asupersync/Cargo.toml` only. The
  dependency-direction CI (A002) forbids it everywhere else in the RABS
  domain layer.

## Upgrade procedure (binding)

A pin advance is a reviewed change that must carry, in the same commit
series:

1. the A010 upgrade report: a diff of Asupersync's public API and feature
   graph intersected with the `rabs-asupersync` adapter surface;
2. a green run of the A009 consumer-driven contract suite against the new
   revision (once that suite exists; until then, a full workspace
   fmt/check/clippy/test run is the floor);
3. an update to this ADR's "Current pin" line with the new revision and the
   evidence for why it is safe;
4. no reinterpretation of durable data: if the new revision changes any
   behavior a RABS schema depends on, the relevant schema/key epochs bump
   per the epoch doctrine.

## Current pin

Current admitted pin: `78b64636e99fea4ea2d868096576021dd3b8e519`
(`asupersync 0.5.0`, the published v0.5.0 release). **Native Linux admission
completed September 13, 2026**, using the independent evidence below.
The preceding pin was `107adf1df8d274b37c6ed9a12471fe3da44429f2`
(advanced via `94217a3`, bead `bd-x7y2r`); published RCH 2.0.0 retains that
older pin and its separate release qualification.

### 0.5.0 consumer review (2026-09-12)

This is the manual A010 review for the consumer migration tracked by
`asupersync-nmg80j` in Asupersync. It does not close the separate A010
automation bead or satisfy requirement 2 without execution.

| Consumed surface | Review and required check |
|---|---|
| `RuntimeBuilder::current_thread`, `Runtime::block_on`, `RuntimeHandle::spawn` | The daemon and worker own their runtimes at their existing top-level entries. These signatures remain available. Run the daemon boot/shutdown tests and existing nested-runtime gate. |
| `Cx::current`, `Cx::spawn`, `JoinHandle::join`, `checkpoint`, `trace` | Existing subsystem admission already propagates spawn refusal. 0.5.0 preserves a held runtime capability mask when installing a context and refuses `Cx::spawn` without SPAWN as `RuntimeUnavailable`. The added native contract verifies refusal before the factory runs, unchanged task/region/budget, restoration, and a successful child returning 42. |
| `ShutdownController` / receiver, Unix and TCP streams, async read/write traits | Existing explicit shutdown subscription and socket calls remain supported. Daemon and real socket tests still have to run; static signature review is not shutdown or wire-compatibility proof. |
| `Actor` implementation in `rabsd::coord::action_actor` | The consumed trait shape remains supported. Upstream changed cooperative yielding and graceful-drain panic handling; retain the existing actor tests and do not infer equivalent scheduling from compilation. |
| `LabRuntime` state, scheduler, reports, virtual time and cancellation injection | Public entry points remain available. Keep all four A009 contracts and G012 cancellation tests, including the different-seed negative. Changes to upstream lab internals require fresh results, not replacement goldens. |
| Feature profile | `default`, `proc-macros`, `test-internals` and `tracing-integration` feature definitions are identical between the two Git pins. All three production edges retain `default-features = false` and only `proc-macros`; `rabsd` retains its existing dev-only `test-internals`. |
| `rabs-cas` FrankenSQLite adapter | Release 2.0.0 uses 0.3.18 with `async-api`, independently bringing registry Asupersync 0.4.11. The main candidate selects `fsqlite =0.4.0` with `async-api` (which enables `native`) to retain the `AsyncConnection` surface and move that graph to 0.5.0. Preserve the release's joined-worker Drop fix and lifecycle regressions. Parameter/value conversions remain applicable. Run H009 reference/candidate differential tests, migration rollback and reopen tests before admitting this storage upgrade. |

The Git-pinned RABS runtime and registry-backed FrankenSQLite runtime are
separate Cargo package identities. They exchange RABS-owned SQL values,
not runtime handles or `Cx` values. This migration changes no durable
schema, key epoch, wire field, or stored identity; existing database
reopen and differential tests are still required to validate that claim.

Required remote checks include the `asupersync_contracts`,
`feature_profile`, `nested_runtime_prohibition` and
`g012_cancellation_every_await` integration targets in `rabs-asupersync`,
the daemon and worker tests, and `rabs-cas` H009 plus migration/reopen
tests. Run them through `RCH_REQUIRE_REMOTE=1 rch exec -- ...`, followed
by the required check/clippy/fmt gates. On 2026-09-12, new remote
executions are held because installed RCH automatically invokes cleanup
that conflicts with the session's no-deletion instruction. No local
Cargo fallback or GitHub Actions run is authorized by this report.

On September 13, release 2.0.0 was published from the separately qualified
commit `3289f5e4e977e001187e48976bcd89e4cca0c752`, retaining the last admitted
Git pin. The concurrent main candidate is not included in those artifacts.
Its merge retains the release's rusqlite 0.40.2 and AsyncConnection adapter;
native-only FrankenSQLite features would hide that API. The lock keeps the
candidate's entire FrankenSQLite family at 0.4.0. Separate main-candidate
Linux workspace check and strict Clippy passed with all targets and features
through the user's requested RCH workflow. Formatting and the candidate
security audit also passed. The adapter library and all six integration
targets passed 90 tests. The database suite passed 238 tests, including both
crash matrices, with one L1 maximum-latency failure on the busy worker. Both
unchanged latency tests passed on quiet CSS using the identical test binary.
The retained daemon and worker binaries passed all 134 and 10 library tests,
respectively, from matching source without recompilation. Thus all 473
required tests have a passing execution, while the original Cargo gate's
exit 101 remains recorded. See `UPGRADE_LOG.md` for source, lockfile and log
identities. This is native Linux admission, not Mac test or release-artifact
qualification. The September 12 hold is historical.

### Pin history

| Revision | Landed in | Note |
|---|---|---|
| `62d398ea17519d7e80cbdb32e062d70647cd58a4` | initial | The commit the six adversarial plan passes examined (2026-08-06). |
| `107adf1df8d274b37c6ed9a12471fe3da44429f2` | `94217a3` | Previous admitted pin; used by RCH 2.0.0. |
| `78b64636e99fea4ea2d868096576021dd3b8e519` | September 13 main integration | 0.5.0; independent native Linux admission above. |

### Evidence for the previous admitted pin

`107adf1df8d274b37c6ed9a12471fe3da44429f2` is upstream `693642963` (`br-asupersync-yqlhh7`) carried
onto the previously reviewed `62d398ea17519d7e80cbdb32e062d70647cd58a4` as branch
`cargo-hygiene/keep-git-source-manifests-parseable`.

- **Zero lib-code drift** relative to the reviewed revision. The only change
  is that the fixture-carrier manifest was made valid TOML; the planner
  script and its contract test now generate the malformed case in a temp
  directory instead of shipping it as a committed fixture.
- Because there is no library-code delta, the master plan's behavioral claims
  about Asupersync (regions, obligations, process groups, ATP
  objects/journals, deterministic lab, QUIC blockers §44) carry over
  unchanged from the reviewed commit. The advance reinterprets no durable
  data, so no schema or key epoch bumps are required (requirement 4).
- Verified at bump time: `cargo metadata` resolves; an isolated repro emits
  zero `unclosed table` lines; `cargo check -p rabs-asupersync` completed
  clean in 94s.
- Requirement 2's floor — a full workspace fmt/check/clippy/test run — was
  met during the v1.0.58 release gate: `cargo fmt --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` both exit 0.

`94217a3` advanced the pin in all four manifests (`rabs-asupersync`,
`rabs-wkr`, and both `rabsd` sections) without updating this ADR or the
pin-drift guard in `rabs-asupersync/tests/feature_profile.rs`. The guard then
caught the divergence during the v1.0.58 release gate — working as designed.
This section closes requirement 3 for that advance. The guard's strictness is
unchanged: it still asserts one exact revision, now this one.

## Consequences

- Builds are reproducible against a known-reviewed substrate; upstream
  churn cannot silently alter RABS semantics (R8 mitigated).
- We deliberately forgo upstream fixes landed after the reviewed commit
  until a revalidated advance; if a needed fix appears upstream, the
  upgrade procedure above is the only path to it.
- The git dependency requires network access on first fetch; the local
  clone at `~/projects/asupersync` contains the pinned commit, and Cargo's
  net.git-fetch-with-cli / offline vendoring remain available if fetch
  becomes a constraint.
