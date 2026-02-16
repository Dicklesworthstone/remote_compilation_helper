# Repo Updater Adapter Contract (`bd-vvmd.3.1`)

## Purpose

RCH offloads builds to remote workers. When a project depends on local path dependencies (for example, `/dp/mcp_agent_mail_rust` depending on `/dp/frankentui`), remote builds fail unless those dependency repos are also present on the worker.

This contract defines a stable integration boundary between RCH and `repo_updater` (`ru`) so RCH can:

1. Discover and converge required repos before remote compilation.
2. Enforce trust boundaries for repo host/path safety.
3. Normalize adapter failures into RCH error taxonomy.
4. Keep behavior deterministic via timeout/retry/idempotency policy.

The implementation lives in `rch-common/src/repo_updater_contract.rs`.

## Scope

This contract covers:

- Stable command surface (`ru list/status/sync/robot-docs/version`).
- JSON envelope expectations from `ru --format json`.
- Version compatibility policy against `ru`.
- Trust/auth/fallback policy for convergence operations.
- Mockable adapter interface for deterministic tests.

This contract does **not** implement orchestration in `rchd` yet; it is the boundary specification consumed by follow-on implementation beads.

## Command Surface

`RepoUpdaterAdapterCommand` maps to explicit CLI invocations:

- `list_paths` -> `ru list --paths --non-interactive --format json`
- `status_no_fetch` -> `ru status --no-fetch --non-interactive --format json`
- `sync_dry_run` -> `ru sync --dry-run --non-interactive --format json`
- `sync_apply` -> `ru sync --non-interactive --format json`
- `robot_docs_schemas` -> `ru robot-docs schemas --format json`
- `version` -> `ru --version`

Each command also declares:

- Expected envelope `command` field.
- Idempotency guarantee:
  - `strong_read_only` for read-only commands and dry-run.
  - `eventual_convergence` for `sync_apply`.

## JSON Contract

Raw adapter output is represented by `RepoUpdaterJsonEnvelope` and aligns with `ru` robot docs:

- `generated_at`
- `version`
- `output_format`
- `command`
- `data`
- optional `meta` (`duration_seconds`, `exit_code`)

RCH uses a normalized response model (`RepoUpdaterAdapterResponse`) to decouple daemon logic from command-specific envelope details while preserving:

- adapter version
- status
- sync summary (when present)
- repo-level records (when present)
- failure payload (when present)

## Timeout/Retry Policy

`RepoUpdaterAdapterContract` defines:

- Per-command budgets (`RepoUpdaterCommandBudget`).
- Global timeout policy (`RepoUpdaterTimeoutPolicy`).
- Retry policy (`RepoUpdaterRetryPolicy`).

Default behavior is tuned for deterministic automation:

- short read/probe timeouts
- longer sync timeout
- bounded retries with exponential backoff

## Version Compatibility Strategy

`RepoUpdaterVersionPolicy` establishes:

- minimum supported version (`1.2.0` default)
- max tested major/minor
- whether to allow newer patch/minor ranges

`evaluate_version_compatibility()` returns explicit compatibility outcomes:

- `compatible`
- `too_old`
- `newer_minor_untested`
- `newer_major_unsupported`
- `invalid_version`

This gives future beads a deterministic place to decide fail-open vs fail-closed behavior.

## Trust and Auth Boundaries

`RepoUpdaterTrustBoundaryPolicy` enforces:

- canonical root `/data/projects`
- required alias mapping `/dp -> /data/projects`
- host allowlist (`github.com` by default)
- optional rejection of local-path repo specs

`RepoUpdaterAuthPolicy` documents adapter auth expectations and required/redacted env variables.

## Error Normalization

Adapter failures are classified as `RepoUpdaterFailureKind` and mapped to RCH `ErrorCode` via `map_failure_kind_to_error_code()`.

This keeps downstream diagnostics consistent with the rest of RCH error handling.

## Fallback Behavior

`RepoUpdaterFallbackPolicy` supports:

- `fail_open_local_proceed` (default): continue remote flow without convergence preflight blocking local progress.
- `fail_closed_block_remote_build`: block remote path when repo convergence is mandatory.

Default aligns with RCH fail-open philosophy while keeping a documented strict mode.

## Test Strategy

Unit tests in `rch-common/src/repo_updater_contract.rs` cover:

- contract validation invariants
- command-surface stability
- projects-root/alias policy
- host allowlist enforcement
- version compatibility matrix
- exit-code mapping
- failure-to-error mapping
- invocation env construction
- mock adapter deterministic behavior
- request/response schema checks and parser compatibility

E2E script `tests/e2e/repo_updater_contract.sh` covers:

- targeted unit suite execution
- live `ru robot-docs schemas` probe (if `ru` executable is available)
- envelope/sync schema field assertions via `jq`

## Why This Matters for the Overarching Goal

This contract is the foundation for reliable repo convergence before offloaded builds. Without a strict boundary:

- workers can drift from host repo topology
- path dependencies fail nondeterministically
- integration errors become hard to classify/remediate

By locking command/output/compatibility policy now, subsequent implementation beads can focus on orchestration and performance rather than interface ambiguity.
