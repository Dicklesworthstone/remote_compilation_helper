# ft-4tp7g Golden Corpus

This corpus freezes the machine-readable shapes that regressed while using RCH
from FrankenTerm agent sessions.

Fixtures keep raw inputs beside canonical expected JSON. Tests compare
`serde_json::Value`, so object key order is not meaningful. Dynamic fields are
scrubbed out of the fixtures: timestamps, PIDs, build IDs, socket paths, host
temp directories, and real hostnames. Controlled fixture worker IDs, status
strings, reason codes, selected thresholds, and slot counts are intentionally
not scrubbed.

If a behavior change is intentional, rerun the focused test, review the emitted
expected/actual hash pair, update only the relevant `expected_*` field, and
record both hashes in the Beads closeout. Do not bless a diff that removes a
stable reason code or turns a structured parse/internal error into a config
error.
