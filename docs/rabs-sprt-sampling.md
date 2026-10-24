# Evidence-driven verification floors for live dependency replay

`RABS_SPRT_SAMPLING=1` opts a newly started daemon into additional verification
requirements for the existing `rustc-dependency-compile` class. `true` and `on`
are also accepted. The setting is off by default and read once per process.
Explicit `0`, `false`, and `off` select the fixed policy. Any other supplied
value, including empty or non-Unicode data, refuses live SPRT evaluation rather
than silently selecting fixed replay. This refusal occurs during consultation;
installing the code does not restart or reconfigure a running daemon.
The normal `RABS_LIVE_DEPENDENCY=1` opt-in remains independently required for
live Cargo dependency serving.

**This mode initially prevents every eligible cache replay.** It requires
69,762 credited independent comparisons before its first promotion. It is a
qualification mode, not an immediate build-speed improvement. Existing
publication, per-action comparison, class quarantine, release, output closure,
lease, installation and capture-acknowledgment rules remain in force.

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

| Credited class comparisons | Verification floor | Live replay ceiling after a comparison |
|---|---|---|
| 0–69,761 | 100% | 0 |
| 69,762–139,523 | 25% | 3 |
| 139,524–209,285 | 5% | 19 |
| 209,286 | 1% | 99 |

The live coordinator now obtains its final ceiling from
`SamplingPolicy::replay_install_limit` under the same metadata lock as receipt
validation and installation. With SPRT enabled, the qualified 19/99 ceilings
replace the earlier independent 16-install cap. With SPRT disabled, the existing
16-install policy is unchanged. The initial two attributable per-action
comparisons are still required even for a class qualified at the 1% floor.

`None` from the ceiling adapter selects the caller's existing fixed policy;
`Some(0)` is a verification requirement, never permission to fall back to 16.
Malformed configuration, unreadable evidence, and failed checkpoint/promotion
writes propagate as errors. The adapter reruns the existing sampling gate rather
than deriving a second interpretation of class safety or evidence.

**Policy changes do not reset spending.** Both modes use the same existing
`rabs-live-replay-install-v1` receipts for the latest independent comparison.
For example, after 16 fixed-policy installations, a qualified 99 ceiling permits
at most 83 more. Restarting with fixed policy after those installations permits
none until a new admitted comparison. Previews do not spend; failed or partial
installations conservatively spend once, before any output write.

These are boundaries of the configured Bernoulli model, not evidence that
actual build outcomes are independent or identically distributed, not a measured
1e-6 divergence rate, and not an overall repeated-testing error guarantee.
The stronger any-failure veto remains in force at every stage. Statistical
model qualification and performance qualification remain separate work.

## Which evidence counts

Only a `rabs-live-verification-v1` receipt from the existing publication path
can be considered. It must match a positive verification sample at the exact
sequence, a recorded attempt with a nonempty worker identity and its action
generation, the currently published manifest, and the descriptor-derived class
receipt. The initial winning attempt is excluded. Raw samples, unknown or
foreign attempts, private classes, wrong manifests, and duplicate offers cannot
earn credit. A recorded worker identity does not itself prove independence.

The reducer processes at most 128 new decision-journal rows per check using a
rowid range cursor. Unrelated receipt payloads are not loaded. The final ceiling
adapter can perform another bounded check in the same live request. Rowid selects
a scan position only; a stable action/attempt marker supplies deduplication.
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

The ladder's Rust regressions exercise metadata interfaces, both SQLite
backends, database reopening, attribution, duplicate suppression, interrupted
checkpointing, negative-evidence ordering, and cadence. Additional ceiling tests
cover every stage, mode parsing, spent-receipt preservation, policy/class holds,
invalid checkpoints, and empty-worker attribution.

`rabsd/tests/live_sprt_budget.rs` uses actual CAS and installed output bytes to
exercise the restricted edge-to-coordinator path. Its fresh-process scenarios
cover 0/3/19/99 ceilings, restarts, 24 competing installers sharing 19 permits,
mode switches, and invalid configuration. Qualification checkpoints are
explicitly injected fixtures for testing the consumer, **not earned compiler
comparisons or production qualification evidence**.

`tests/test_rabs_sprt_evidence.py` extracts the exact SQL from the Rust module.
Its native SQLite checks independently verify the high-precision boundary,
rowid query plan, all three crossings from 209,286 distinct synthetic relational
proofs, crash cuts, replay deduplication, and seeded histories. Its Python
reducer is a model: a passing result does not compile or execute the Rust code,
validate FrankenSQLite, prove a Cargo cache hit, or measure fleet performance.

```sh
python3 -m unittest discover -s tests -p test_rabs_sprt_evidence.py -v
rch exec -- cargo test -p rabs-cas --lib serving_sample_gate --locked
rch exec -- cargo test -p rabsd --test live_replay --test live_class_safety --test live_sprt_budget --locked
```

This increment completes the evidence-qualified live ceiling handoff, not class
repair/re-enablement, production qualification, or automatic Cargo-to-remote-
worker dispatch. `bd-okthi` remains open until its original runtime and rollout
requirements are met. Do not enable this mode to obtain a speedup claim from a
small fixture or weaken the evidence threshold to pass a test.
