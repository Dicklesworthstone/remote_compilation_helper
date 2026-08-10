# RABS Test-Log Standard (v1) — bead T053

Every RABS suite (unit, property, lab, chaos, soak, e2e) emits JSON-line
records so a green checkmark is backed by machine-readable evidence.
Library: `rabs_protocol::test_log` (`TestLogger`). Format version:
`TEST_LOG_STANDARD_VERSION = 1`.

## Record format

One JSON object per line. Required fields on every record:

| field | meaning |
|---|---|
| `v` | standard version (integer, currently `1`) |
| `suite` | `<class>/<name>`, e.g. `unit/snapshot`, `e2e/freshness` |
| `test` | test function name |
| `trace` | causal trace ID, unique per test run, shared by all its records |
| `step` | `start`, `finish`, or a suite-defined step name |
| `elapsed_us` | microseconds since the test's `start` record |

Optional per-record fields:

- `seed` — the deterministic-replay seed (REQUIRED whenever the test
  uses randomness);
- attribution facets per the G001 tracing contract, emitted when known:
  `region`, `authority`, `operation`, `generation`, `action`, `attempt`;
- suite-defined string fields (bounded to 2048 chars by the library).

The terminal record has `step = "finish"` plus:

- `outcome` — `pass` | `fail`;
- `evidence` — what was PROVEN (not "it ran"); bounded to 4096 chars.

## Redaction (A007)

The emission path is the redaction boundary:

- env-shaped observations go through `env_field` (the A007 classifier —
  secret-class values are redacted before serialization);
- path observations go through `path_field` (user home replaced);
- all free-text fields are bounded excerpts.

A suite MUST NOT bypass the library to print raw JSON.

## Adoption rules

- New suites adopt at creation; the T002 core deterministic scenarios
  adopt as part of their own bead.
- Logs write to stderr locally and to a per-suite `.jsonl` artifact in
  CI, feeding the R001 decision-receipt pipeline and the T012 failing-
  trace minimizer.
- A failing test's records MUST include enough fields to replay it:
  seed, inputs (redacted), and the divergence evidence.

## Example

```json
{"v":1,"suite":"unit/snapshot","test":"mutation_retry","trace":"unit-snapshot-mutation_retry-42","step":"start","elapsed_us":2,"seed":42,"region":"edge"}
{"v":1,"suite":"unit/snapshot","test":"mutation_retry","trace":"unit-snapshot-mutation_retry-42","step":"scan","elapsed_us":180,"seed":42,"region":"edge","files":"12"}
{"v":1,"suite":"unit/snapshot","test":"mutation_retry","trace":"unit-snapshot-mutation_retry-42","step":"finish","elapsed_us":1834,"seed":42,"region":"edge","outcome":"pass","evidence":"retry forced; manifest == post-mutation world"}
```
