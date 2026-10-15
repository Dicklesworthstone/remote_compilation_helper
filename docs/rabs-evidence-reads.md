# Evidence-query scaling on live cache replay

Every live cache replay still reads current verification and class safety
state under the existing CAS lock. No positive verdict, absence of failure,
class membership, or installation permission is cached by this optimization.

At exclusive store mount, after the normal metadata schema migrations and
before reconciliation or coordinator startup, RABS installs two ordinary
secondary indexes in one transaction:

* Verification outcome and action identity.
* Serving disposition and action identity.

These are non-authoritative access paths, not materialized evidence summaries.
They add no trials, credits, publications, receipts, or schema-version claims.
Core schema versioning is unchanged. Library/older clients remain semantically
correct without the indexes; the narrow `prepare_serving_indexes` API exposes
only the fixed index profile, not arbitrary external SQL access. An interrupted
profile install rolls back its DDL. Mount errors retain their typed failure;
index creation is never deferred onto a waiting compiler's lookup.

The class-negative query now expresses `passed != 1` as two indexable ranges,
`passed < 1 OR passed > 1`. It still refuses non-Boolean outcome flags rather
than treating only zero as adverse. Together with the disposition index, this
avoids scanning every healthy sample and every healthy action to discover that
no class-wide veto exists. An actual negative row or newly recorded quarantine
is visible on the next query. Receipt-bound membership and the order of incident,
verification, action-quarantine, and serving-quarantine checks are unchanged.

Index creation takes time and extra disk space on a populated store; subsequent
writes maintain the indexes. Large negative histories still require checking
negative witnesses against class membership. This does not make all serving
queries constant-time, prove a Cargo speedup, enable a cache class, relax a
sampling floor, or implement remote per-action dispatch.

`tests/test_rabs_evidence_queries.py` executes the exact production predicates
and index DDL against native SQLite. It compares the prior and new predicates,
checks malformed flags, class attribution, newly arriving negative evidence,
transaction rollback, reopening, and query plans. Its optional `benchmark`
function compares both query versions against the same unchanged 250,000-sample
dataset; that number concerns one SQL query, not an end-to-end Rust/Cargo build.

Rust regressions exercise the index profile on both metadata engines and retain
all original class-safety regressions. The authoring environment has no Rust
toolchain; adding these tests is not evidence that they ran.

```sh
python3 tests/test_rabs_evidence_queries.py -v
rch exec -- cargo test -p rabs-cas --lib read_indexes --locked
rch exec -- cargo test -p rabs-cas --lib serving_sample_gate --locked
rch exec -- cargo test -p rabsd --lib janitor --locked
```
