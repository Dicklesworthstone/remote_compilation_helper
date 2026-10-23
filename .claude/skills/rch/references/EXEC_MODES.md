# `rch exec` Modes: Proof, Job, Clean-Overlay, Receipts, Envelope

## Contents

- [Plain `rch exec`](#plain-rch-exec)
- [Strict Remote (Proof Mode)](#strict-remote-proof-mode)
- [Shell-Wrapped Cargo Is Refused (`RCH-E301`)](#shell-wrapped-cargo-is-refused-rch-e301)
- [Job Mode (`--job`, `--result-dir`)](#job-mode---job---result-dir)
- [Clean Git Overlays (`--base`, `--clean-overlay`)](#clean-git-overlays---base---clean-overlay)
- [Source-Content Receipts (`--source-content-receipt`)](#source-content-receipts---source-content-receipt)
- [The Exec Result Envelope (`--json`)](#the-exec-result-envelope---json)
- [Remote Source-Authority Locks](#remote-source-authority-locks)
- [Exit Codes on the Exec Path](#exit-codes-on-the-exec-path)
- [Flag Conflicts](#flag-conflicts)

`rch exec -- <command>` is the direct offload path (the PreToolUse hook rewrites
intercepted commands to exactly this). Flags, verbatim from `rch/src/main.rs`:

| Flag | Meaning |
|---|---|
| `-b, --base <COMMIT>` | Git commit used as the clean source-tree baseline (requires `--clean-overlay`) |
| `--clean-overlay` | Transfer a clean Git baseline plus only explicit overlay paths (requires `--base`) |
| `-o, --overlay-path <PATH>` | Repository-relative file/dir to overlay (repeatable) |
| `--no-overlay` | Clean baseline with no working-tree overlay |
| `--source-content-receipt` | Emit a worker-verified per-root manifest of the exact transferred bytes |
| `--job` | Admit an arbitrary NON-compilation job |
| `--result-dir <DIR>` | Repo-relative dir to sync back after a job, including on non-zero exit (repeatable, requires `--job`) |
| global `-j/--json`, `-F json\|toon` | Emit the exec result envelope on stdout |

## Plain `rch exec`

```bash
rch exec -- cargo check --workspace --all-targets
```

Fail-open: if anything upstream of the remote command fails, it runs locally and
prints `[RCH] local (<reason>)` (see `FAIL_OPEN.md`). Remote command output
streams to **stderr**; stdout stays clean (envelope-only in `--json` mode).

`CARGO_TARGET_DIR`, `TMPDIR/TMP/TEMP`, `GOCACHE/GOMODCACHE/GOPATH` are always
rewritten on the worker to managed paths under the remote project root
(`.rch-target-*`, `.rch-tmp`, `.rch-go/*`) — you cannot point a remote build at
an arbitrary worker directory, and you don't need `env CARGO_TARGET_DIR=…` in
front of the command any more. The default remote target-dir shape is
**pooled** (`.rch-target-<worker>-pool-<key>`, reused across jobs for warm
incremental builds); `RCH_DISABLE_TARGET_REUSE=1` reverts to per-job dirs.

## Strict Remote (Proof Mode)

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --workspace
```

Refuses every local fallback instead of silently building locally. This is the
right form for *proof* ("this passed on a worker") and for the "is the offload
path healthy at all?" check — a failure is loud (exit 103/1 with the reason)
rather than a 38-second local build that looks fine.

`RCH_REQUIRE_REMOTE` takes precedence over `RCH_FORCE_REMOTE` (which only
bypasses the local-time/speedup gating and still fails open). A box with
`general.role = "dispatcher"` defaults to strict remote when neither variable is
present.

Retryable refusals (no worker assignable now, daemon momentarily unavailable)
exit **103**; `non-compilation command` and `config unavailable` exit **1**.

## Shell-Wrapped Cargo Is Refused (`RCH-E301`)

```bash
rch exec -- bash -lc "cargo test -p a && cargo test -p b"    # REFUSED
```

Shell-wrapped cargo (`sh -c`, `bash -lc`, `&&` chains inside a shell string) is
rejected before remote execution *and* before local fallback: rch cannot bind
the output path, so the build could succeed remotely while leaving the caller's
local binary stale. You get `[RCH-E301]`, exit 1, empty stdout. Run separate
direct invocations instead:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p a
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p b
```

Non-compilation `sh -c` scripts are unaffected (use `--job` if they must run
remotely).

## Job Mode (`--job`, `--result-dir`)

```bash
rch exec --job -- ./run_shards.sh
rch exec --job --result-dir fuzz/corpus --result-dir crashes -- ./fuzz_target.sh
```

- Bypasses **only** the compilation classifier. The command rides the normal
  selection / sync / execute / heartbeat / release rails. The PreToolUse hook
  never sets `--job`, so ordinary commands can never be auto-delegated this way.
- Syncs **no artifacts** back by itself; declare `--result-dir` (repo-relative,
  repeatable, duplicates collapsed) to bring directories back — **including on
  non-zero exit** (crash logs, partial corpora, sharded test output).
- The remote exit status surfaces **verbatim**: no toolchain / worker-env rerun
  heuristics apply.
- A declared result dir that is missing or only partially transferable fails the
  invocation loudly with `RCH-E309`, exit **102**, regardless of the job's own
  exit. An invalid `--result-dir` value (absolute, traversing) is refused up
  front with exit 2 / `RCH-E001`.
- **Queueing:** job requests that lose every worker to active-same-project
  exclusion are queued (`RCH_QUEUE_WHEN_BUSY`, default on) instead of refused —
  an N-shard burst larger than the worker count spreads one shard per worker
  and queues the rest, on initial admission and on queue polls. Affinity
  fallback is suppressed in job mode so a queued shard cannot escape onto a
  busy worker. Compilation requests are unchanged.

## Clean Git Overlays (`--base`, `--clean-overlay`)

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path src/lib.rs --overlay-path tests/focused.rs -- cargo test --test focused

RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay \
  -- cargo check --workspace --all-targets
```

For shared working trees where other agents' uncommitted edits must not leak
into your build. The client resolves `--base` to a commit, streams that Git
archive into a fresh isolated worker path, then uploads only the literal
`--overlay-path` selections (modified and untracked files allowed). Exactly one
of `--overlay-path…` or `--no-overlay` is required.

Preconditions: run from the **Git toplevel** (otherwise `clean-overlay exec must
run from the Git toplevel (current: …, toplevel: …)`), and `--base` must be a
non-empty revision. Fails closed on: selected deletions, absolute/traversing paths, Git metadata,
non-ASCII/backslash/control-character paths, case-only ambiguous spellings,
overlay symlinks, empty overlay dirs, submodules, `export-ignore`/`export-subst`
attributes. Overlays are re-fingerprinted after upload; a change during
admission or transfer refuses execution. Clean-overlay implies remote-only
execution even without `RCH_REQUIRE_REMOTE`. It also admits the read-only
`cargo fmt --check`, which the ordinary classifier leaves local.

Scope: one Git repository; in-repo workspace members are in the archive;
**external path dependencies are outside the source-identity guarantee**.
The per-run remote root (`{remote_base}/{project}/{nonce}`) is reaped at
teardown once artifacts/result dirs are retrieved (bead `bd-p1vlb`, soak still
open); `rch cache clean --base <PATH>` sweeps drifted staging bases.

## Source-Content Receipts (`--source-content-receipt`)

```bash
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- cargo test --locked --workspace
```

Implies strict remote. Single-worker, fail-closed transfer of the exact Cargo
path-dependency closure, each root at an invocation-unique worker path, with
checksum comparison, and every selected file reopened before and after the
command. Emits a `rch.source_content_receipt.v1` JSON binding `worker_id`,
`build_id` (decimal string), `command_sha256`, `command_exit_code`,
`root_count`, per-root manifests (`schema` = `rch.source_content_root.v1`, `ordinal`, `project_id`,
`local_root`, `remote_root`, `root_hash`, `is_primary`, `mode`, `filter_policy`,
`file_count`, `byte_count`, `files[{path,sha256,byte_count,executable}]`,
`content_root`) and `receipt_root`.

Refuses (no receipt) on: unproved dependency closure, transfer delta, worker
verification error, local lasting change, retry, local fallback, clean-overlay,
non-Unix (non-rsync) transport. Caps: 100k files, 8 GiB, 32 MiB manifest /
receipt, 180 s remote verify.

The receipt is emitted after the post-command source barrier but **before**
artifact retrieval completes — artifact-grade callers must also retain the
later retrieval / terminal transcript.

## The Exec Result Envelope (`--json`)

```bash
rch --json exec -- cargo test -p foo    # or RCH_JSON=1 / RCH_OUTPUT_FORMAT=json|toon
```

Exactly **one** NDJSON line on stdout per invocation, at the terminal path,
while the remote command's own output goes to stderr. Never emitted on the
hook path (hook stdout stays protocol-clean).

```json
{"api_version":"1.0","command":"cargo test -p foo","outcome":"completed",
 "location":"remote","worker_id":"vmi1","remote_exit_code":101,"duration_ms":8123,
 "timing":{...},"result_dirs":[{"path":"crashes","files":3,"bytes":4096,"status":"ok"}]}
```

- `outcome` describes **delivery**, not build success: `completed` (remote
  command ran, outputs handled, whatever its exit code) · `refused` ·
  `transport_error` · `collection_error` (rch itself failed).
- `location` ∈ `remote` | `local`; `fallback_reason` carries the `[RCH] local
  (…)` reason or fixed tokens `shell-wrapped cargo command`,
  `fail_closed_no_local_fallback`, `worker_env_remediation`.
- `error_code` appears on the `RCH-E301` refusal (`outcome: refused`) and on the invalid `--result-dir` envelope (`RCH-E001`, `outcome: collection_error`).
- `result_dirs[].status` ∈ `ok` | `missing` | `transfer_failed`.

Why it exists: exit status alone cannot distinguish "remote command exited
non-zero" from "rch fell back locally and *that* exited non-zero" from "rch
itself failed" — `RCH-Ennn` are diagnostic identifiers, not an exit namespace.

```bash
# scripted proof: remote AND passed
rch --json exec -- cargo test -p foo 2>/dev/null \
  | jq -e '.outcome=="completed" and .location=="remote" and .remote_exit_code==0'
```

## Remote Source-Authority Locks

For ordinary (non-overlay, non-receipt) exact-closure syncs, rch holds an
exclusive `flock` on every mutable canonical source root on the worker from
before the first rsync until **Cargo exits**, via one persistent SSH session
(lock files under `/tmp/rch-source-authority-locks/<blake3>.lock`). This stops
another invocation from replacing a manifest while rustc is still reading the
closure. Verbose lines:

```
[RCH] waiting for N remote source-authority lock(s) on <worker>
[RCH] acquired … / [RCH] released … after Cargo exit
```

A build that appears stuck at "waiting for … source-authority lock" is
**contending with another invocation on a shared path dependency**, not hung.
Lock loss is fail-closed: if the holder died before Cargo started, the run
errors rather than proceeding without authority.

## Exit Codes on the Exec Path

| Exit | Meaning |
|---|---|
| 0 | command succeeded |
| 1 | build/compilation error, or a *permanent* fail-closed refusal (`RCH-E301` shell-wrapped, `non-compilation command`, `config unavailable`) |
| 2 | invalid `--result-dir` (`RCH-E001`) |
| 101 | `cargo test` ran, some tests failed |
| 102 | remote command succeeded but artifacts / declared result dirs could not be transferred back (`RCH-E309`) |
| 103 | *retryable* fail-closed refusal under `RCH_REQUIRE_REMOTE` / shim / dispatcher role |
| 128+N | killed by signal N (137 = external-timeout SIGKILL) |

## Flag Conflicts

`--job` conflicts with `--clean-overlay` and `--source-content-receipt`;
`--source-content-receipt` conflicts with `--clean-overlay`; `--result-dir`
requires `--job`; `--base`/`--overlay-path`/`--no-overlay` require
`--clean-overlay`; `--overlay-path` and `--no-overlay` are mutually exclusive.
