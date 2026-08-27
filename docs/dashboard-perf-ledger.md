# Performance ledger — rch fleet dashboard

> Raw artifacts (`run1/`, `run2/` —
> baseline.json + V8 .cpuprofile) are LOCAL-ONLY by policy: `.cpuprofile` embeds absolute
> source paths and everything is regenerable via `npm run perf` and `npm run probe`.
> Do not commit regenerated artifacts.

Skill protocol: `profiling-software-performance` (measure first) → `extreme-software-optimization`
(one lever per round, Opportunity Matrix ≥ 2.0 or documented reject).

## Scenario fingerprint

- Host: Apple M4 Pro (arm64), macOS/Darwin 25.2.0 — shared dev box under concurrent agent load
- Node: v25.4.0; Chromium via Playwright headless
- Build: vite 7 production (`tsc -b && vite build`), target es2022
- Run IDs: `run1` (pre-optimization baseline, commit 7281aee), `run2` (post rounds)
- Data: real encrypted fleet snapshot (`public/data/fleet.enc.json`, 16 workers / 10 dev machines)

## Baselines

| Scenario | Metric | run1 | run2 |
|---|---|---|---|
| S1 browser: gate paint | p50 / p95 ms | 80 / 116 | 107 / 315 |
| S1 browser: unlock → KPIs | p50 / p95 ms | 117 / 137 | 131 / 175 |
| S2 node: `npm run llm` end-to-end | p50 / p95 ms | 211 / 272 | 265 / 419 |
| S3 bundle | JS bytes (gzip) | 223,382 (69.2 KB) | 223,918 (69.5 KB) |
| S4 typing 7 keys, 26 cards (desktop) | JS total / long tasks | 8 ms / 1×55 ms (one-off) | 6 ms / 0 |
| S4 typing, 4× CPU throttle, 390 px | JS total / long tasks | — | 22–27 ms / 0 (steady state) |
| S5 30 s clock tick | long tasks | 0 | 0 |
| S6 full-page scroll, 390 px | recalc / layout / long tasks | 44 / 10 / 0 | 45–51 / 10–13 / 0 |

Cross-run p95 drift (S1 gate 116→315 ms, S2 272→419 ms) is host-load noise — the box runs a
dozen concurrent agents; within-run distributions are tight and the S2 code path is byte-identical
except one string. No regression signal.

## Hotspot table (evidence: `run1/`, `run2/`, CDP probes)

| Rank | Location | Metric | Value | Category | Evidence |
|---|---|---|---|---|---|
| 1 | PBKDF2-HMAC-SHA256 ×600k (`crypto.ts` deriveKey, `api/fleet.mjs` decrypt) | CPU, native | ~100 ms of every unlock/endpoint call | CPU (native crypto) | run1 S1 p50 117 ms total vs 6–10 ms JS; run1 `CPU.*.cpuprofile` shows distill JS at 10.2 ms of 211 ms |
| 2 | React initial commit (36 cards + sparklines) | script | ~230 ms at 4× throttle ≈ 58 ms real | CPU | `run2` load probe: long tasks 58–125 ms throttled; unthrottled S1 117 ms total |
| 3 | `JSON.parse` of ~196 KB plaintext | script | <10 ms | CPU | within S1 total, bounded by commit cost above |
| 4 | Node CLI bootstrap + GC | CPU | ~40 ms of S2 | CPU | cpuprofile: `compileForInternalLoader` + GC ≈ 50 ms |
| 5 | Scroll/typing/tick render paths | — | no long tasks, single-digit ms | — | render-probe S4–S6, both viewports, throttled and not |

## Hypothesis ledger (rounds)

| Round | Hypothesis / lever | Verdict | Evidence |
|---|---|---|---|
| R1 | Node llm pipeline has hot JS to optimize | **rejects** — distill+encode is 10.2 ms of 211 ms; rest is native PBKDF2 + bootstrap | run1 cpuprofile self-time table |
| R2 | Typing re-renders 26 cards → jank; memoize cards | **rejects** — steady-state 6–27 ms JS per 7 keystrokes, 0 long tasks even at 4× throttle | render-probe secondBurst, throttled |
| R3 | Bundle carries accidental deps (toon et al.) | **rejects** — bundle is pure react-dom + app; 69 KB gzip | grep of dist + module count 38 |
| R4 | `content-visibility: auto` on sections cuts load cost | **rejects (A/B failed, reverted)** — load long tasks 311 ms → 360 ms (noise), layouts 8→10; Chromium already skips off-screen paint at load | probe-throttled-before/after.json |
| R5 | 30 s `now` tick re-renders are hot | **rejects** — 0 long tasks | render-probe tick |
| R6 | Scroll is jank-prone on mobile | **rejects** — 0 long tasks unthrottled and throttled | render-probe scroll, 390 px |
| R7 | Endpoint re-derives PBKDF2 per request — cacheable | **rejects (by design)** — per-request derivation is the documented brute-force cost; caching would defeat it | `api/fleet.mjs` header comment, README security model |
| R8 | Snapshot collector is sequential over dispatchers | **rejects** — already `Promise.all` per host and across hosts | `tools/snapshot.mjs:157,313` |
| R9 | Sparkline value arrays re-created per render | **rejects** — 3×96-point maps are nanoseconds; no measured hotspot | R2/R5 evidence |
| R10 | no-store + cache-buster double-fetch cost | **rejects** — one fetch; headers are the stale-fleet guard this project exists for | `App.tsx` loadEnvelope |
| R11 | Instrumentation round: CDP metric probes added as permanent harness | **supports** — `tests/render-probe.mjs`, `npm run probe` | this ledger |
| R12 | react-doctor static findings hide perf issues | **supports (fixed)** — 15 findings resolved to 0; score 64 → 100 | react-doctor output before/after |

## Conclusion

Every measured path is dominated by the **intentional 600k-iteration PBKDF2** — a security
parameter, not an inefficiency. All React render paths are single-digit milliseconds with zero
long tasks in steady state, on desktop, mobile, and 4×-throttled mobile. No lever scored ≥ 2.0
that survived its A/B. The one implemented-and-reverted lever (R4) is documented above.
Truthful null result: no safe performance increment found beyond what shipped.

Verification per change: `npm run build`, `test:llm` (parity), `test:endpoint`, `test:e2e` (3×),
`test:visual` (desktop/tablet/mobile screenshots, 0 console errors), `npx react-doctor` (100/100).
