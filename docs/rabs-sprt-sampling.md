# Evidence-driven verification floors for live dependency replay

`RABS_SPRT_SAMPLING=1` opts a newly started daemon into additional verification
requirements for the existing `rustc-dependency-compile` class. `true` and `on`
are also accepted. The setting is off by default and read once per process.
The normal `RABS_LIVE_DEPENDENCY=1` opt-in is still independently required for
live Cargo dependency serving. No daemon, worker, or Cargo configuration is
changed by installing this code.

**This mode initially prevents every eligible cache replay.** It requires
69,762 credited independent comparisons before its first promotion. It is a
qualification mode, not an immediate build-speed improvement. Existing
publication, per-action comparison, class quarantine, release, output closure,
lease, installation and capture-acknowledgment rules are not relaxed.

## Qualification and effective replay limits

The parameters are the original `bd-okthi` contract: Bernoulli divergence
hypotheses `p0=0.000001`, `p1=0.0001`, and `alpha=beta=0.001`. Any negative
evidence already stops the entire live class through the existing quarantine
gate. For the remaining zero-failure sequence, the accept-H0 boundary is:

```text
LLR(n) = n * ln((1 - p1) / (1 - p0))
accept-H0 when LLR(n) <= ln(beta / (1 - alpha))
smallest integer n = 69762
LLR(69761) = -6.906687793374887577...
LLR(69762) = -6.906786798374720935...
boundary  = -6.906754778648553518...
```

Three disjoint windows qualify the 100 -> 25 -> 5 -> 1 percent verification
floors. Comparisons used in one window cannot be reused by the next. The
implementation uses the integer crossing, not platform-dependent floating-point
comparisons. Each promotion records the parameters, window and cumulative
counts, log-likelihood ratio, and boundary in the existing decision journal.

| Credited class comparisons | Verification floor | Ladder replay ceiling after a comparison | Effective ceiling with existing live gate |
|---|---|---|---|
| 0–69,761 | 100% | 0 | 0 |
| 69,762–139,523 | 25% | 3 | 3 |
| 139,524–209,285 | 5% | 19 | 16 |
| 209,286 | 1% | 99 | 16 |

The existing **16-install ceiling remains independently enforced**. Thus the
last two qualified floors do not currently permit 19 or 99 installations.
A floor is a minimum verification requirement, not a measured sampling rate.
The new gate examines existing per-action installation receipts; it never
spends or renews an installation permit itself. Preview cannot spend one.

These are boundaries of the configured Bernoulli model, not evidence that
actual build outcomes are independent or identically distributed, not a measured
1e-6 divergence rate, and not an overall repeated-testing error guarantee.
The stronger any-failure veto remains in force at every stage. Statistical
model qualification and performance qualification remain separate work.

## Which evidence counts

Only a `rabs-live-verification-v1` receipt from the existing publication path
can be considered. It must match a positive verification sample at the exact
sequence, a recorded attempt and its action generation, the currently published
manifest, and the descriptor-derived class receipt. The initial winning attempt
is excluded. Raw samples, unknown or foreign attempts, private classes, wrong
manifests, and duplicate offers cannot earn credit.

The reducer processes at most 128 new decision-journal rows per check using a
rowid range cursor. Unrelated receipt payloads are not loaded. Rowid selects a
scan position only; a stable action/attempt marker supplies deduplication.
Every credited attempt is marked consumed before the positive checkpoint is
advanced. An interrupted or ambiguous write may permanently lose positive
credit, but cannot count that attempt again. Reopening the database, re-offering
old comparisons, or rewinding a cursor cannot restore consumed credit. A cursor
invalidated by journal compaction can undercount; it is not an authority token.

Checkpoint, consumed-attempt and promotion records use separate versioned kinds
in the existing metadata journal. No schema migration, second cache, or new
dependency is introduced. The caller holds the existing CAS lock throughout the
check and subsequent installation. Metadata errors fail closed. No decision is
cached across requests; the existing negative-evidence checks always run first.

`ClassVerificationRequired` reports the descriptor class, credited comparisons,
and current verification floor. It requests ordinary execution, not class
repair. No automatic re-enablement after divergence is provided, and no retained
manifest, incident, candidate pin, or installed artifact is erased.

## Validation and remaining scope

Ten Rust regressions exercise the actual metadata interfaces, including both
SQLite backends, database reopening, proof attribution, duplicate suppression,
interrupted checkpointing, negative-evidence ordering, and replay cadence. They
use synthetic action/worker evidence, not real compiler execution. The existing
`serving_sample_gate` CI test selection includes these tests.

`tests/test_rabs_sprt_evidence.py` extracts the exact SQL from the Rust module.
Its native SQLite checks independently verify the high-precision boundary,
rowid query plan, all three crossings from 209,286 distinct synthetic relational
proofs, crash cuts, replay deduplication, and seeded histories. Its Python
reducer is a model: a passing result does not compile or execute the Rust code,
validate FrankenSQLite, prove a Cargo cache hit, or measure fleet performance.

```sh
python3 -m unittest discover -s tests -p test_rabs_sprt_evidence.py -v
rch exec -- cargo test -p rabs-cas --lib serving_sample_gate --locked
rch exec -- cargo test -p rabsd --test live_replay --test live_class_safety --locked
```

This increment does not replace the fixed live replay ceiling, complete class
repair/re-enablement, qualify production traffic, or connect automatic Cargo
requests to remote workers. `bd-okthi` remains open until its original runtime
and rollout requirements are met. Do not enable this mode to obtain a speedup
claim from a small fixture or weaken the evidence threshold to pass a test.
