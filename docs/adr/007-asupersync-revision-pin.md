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

`62d398ea17519d7e80cbdb32e062d70647cd58a4` (initial; plan-reviewed).

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
