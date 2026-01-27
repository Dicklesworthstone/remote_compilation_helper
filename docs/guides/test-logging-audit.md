# Test Logging Compliance Audit (Initial)

Date: 2026-01-17

This is an initial audit of test logging compliance against the required standard:
- `init_test_logging()` call
- `TEST START: ...` log line
- input/expected/actual logging
- `TEST PASS: ...` log line

## Scope

Searched Rust test sources in:
- `rch/`
- `rch-common/`
- `rchd/`
- `rch-wkr/`
- `rch-telemetry/`

Command summary:
- Total tests (#[test]): 1285
- Files containing tests: 103
- Occurrences of "TEST START": 292
- Occurrences of `init_test_logging`: 290

Note: "TEST START" and `init_test_logging` counts are rough indicators (string occurrence), not exact test-level compliance.

## File-Level Compliance (Initial)

Files missing any "TEST START" string:
- 78 / 103 test files (76%)

Files missing any `init_test_logging` call:
- 77 / 103 test files (75%)

Module breakdown (missing "TEST START"):
- rch: 38 files
- rch-common: 20 files
- rchd: 13 files
- rch-telemetry: 5 files
- rch-wkr: 2 files

Module breakdown (missing `init_test_logging`):
- rch: 41 files
- rch-common: 20 files
- rchd: 13 files
- rch-wkr: 2 files
- rch-telemetry: 1 file

## Top Non-Compliant Files by Test Count (Missing "TEST START")

```
97 rch/src/main.rs
51 rch-wkr/src/toolchain.rs
47 rch-common/src/patterns.rs
41 rch-common/src/types.rs
40 rch/src/commands.rs
32 rch/src/toolchain.rs
31 rch/src/fleet/plan.rs
31 rch/src/fleet/dry_run.rs
29 rch-common/src/toolchain.rs
24 rch/src/fleet/audit.rs
22 rch/src/ui/styled.rs
20 rchd/tests/e2e_daemon.rs
20 rchd/src/config.rs
19 rch/src/ui/progress.rs
18 rch/src/ui/markdown.rs
18 rch-common/src/discovery.rs
17 rch/src/ui/context.rs
17 rch/src/state/primitives.rs
16 rch/src/fleet/preflight.rs
15 rchd/src/api.rs
```

## Top Non-Compliant Files by Test Count (Missing init_test_logging)

```
97 rch/src/main.rs
51 rch-wkr/src/toolchain.rs
47 rch-common/src/patterns.rs
41 rch-common/src/types.rs
40 rch/src/commands.rs
32 rch/src/toolchain.rs
31 rch/src/fleet/plan.rs
31 rch/src/fleet/dry_run.rs
29 rch-common/src/toolchain.rs
27 rch/tests/e2e_hook.rs
25 rch/src/error.rs
24 rch/src/fleet/audit.rs
22 rch/src/ui/styled.rs
21 rchd/tests/e2e_worker.rs
21 rch/src/config.rs
20 rchd/tests/e2e_daemon.rs
19 rch/src/ui/progress.rs
18 rch/src/ui/markdown.rs
18 rch-common/src/discovery.rs
17 rch/src/ui/context.rs
```

## Next Steps

1. Add a shared logging helper (per bead spec) to reduce boilerplate.
2. Prioritize high-test-count files above for compliance updates.
3. Re-run the audit and track compliance rate over time.

---

## Update: 2026-01-27 (bd-2zsu)

### Infrastructure Status: ✅ Complete

**Rust Logging Infrastructure** (`rch-common/src/testing/`):
- `TestLogger` with JSONL output to `target/test-logs/`
- `TestPhase` enum: Setup, Execute, Verify, Teardown
- `TerminalInfo` for TTY/color status capture
- TEST START/PASS/FAIL markers via tracing
- Path resolution fixed to find workspace target/ directory

**Bash Logging Infrastructure** (`scripts/test_lib.sh`):
- `init_test_log <name>` - creates log file, logs TEST START
- `log_json <phase> <message> [<data>]` - JSONL logging
- `log_terminal_info` - captures terminal metadata
- `test_pass`, `test_fail`, `test_skip` - standard exit functions

**Test Convenience Layer** (`rch/tests/common/logging.rs`):
- Re-exports `TestLogger`, `TestPhase`, etc. from rch_common::testing
- `init_test_logging()` for tracing setup
- `test_log!` macro for backwards compatibility

### Current Adoption

**High Adoption Areas:**
- `tests/true_e2e/`: 124 TestLogger occurrences across 13 files
- `rch/tests/compile_context.rs`: Uses TestLogger
- `rch/tests/stream_isolation.rs`: Updated to use TestLogger
- `rch/tests/hook_integration.rs`: Uses TestLogger

**Lower Priority Areas:**
- Unit tests within source files (e.g., `rch/src/main.rs`)
  - These are small, focused tests where TEST START/PASS overhead may be unnecessary
  - Consider updating only integration/E2E style tests

### JSONL Output Format

```json
{"timestamp":"2026-01-27T06:04:31.845Z","test_name":"test_example","phase":"setup","message":"TEST START","duration_ms":0}
{"timestamp":"2026-01-27T06:04:31.860Z","test_name":"test_example","phase":"execute","message":"Running command","duration_ms":15}
{"timestamp":"2026-01-27T06:04:31.862Z","test_name":"test_example","phase":"verify","message":"TEST PASS","duration_ms":17}
```

### Recommendations

1. **For new tests**: Use `TestLogger::for_test("test_name")` with explicit pass()/fail()
2. **For existing E2E tests**: Migrate to TestLogger when touching the file
3. **For unit tests in source files**: Optional - use only if debugging needs arise

