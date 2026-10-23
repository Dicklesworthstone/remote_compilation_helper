# SSH Tuning for RCH

## Contents

- [Defaults Worth Knowing](#defaults-worth-knowing)
- [ControlMaster Default Is OFF](#controlmaster-default-is-off)
- [Keepalives for Long Builds](#keepalives-for-long-builds)
- [Connect / Command Timeouts](#connect--command-timeouts)
- [Authentication Failure Triage](#authentication-failure-triage)
- [Retryable vs Fatal Transport Errors](#retryable-vs-fatal-transport-errors)
- [Known-Hosts Policy](#known-hosts-policy)
- [End-to-End Probe Recipes](#end-to-end-probe-recipes)
- [Multi-Hop / Jump Host](#multi-hop--jump-host)
- [Quick Knob Cheat Sheet](#quick-knob-cheat-sheet)

Most "intermittent worker failure" reports trace to SSH transport quirks: stale ControlMaster sockets, broken keepalives, or auth misconfiguration. RCH gives you knobs for all of them.

---

## Defaults Worth Knowing

`rch_common::ssh::SshOptions::default()`:

```text
connect_timeout       = 10s
command_timeout       = 300s
server_alive_interval = None   (OpenSSH default; keepalive disabled)
control_persist_idle  = None   (uses ControlPersist=yes when control_master is true)
control_master        = false  (default OFF — see history below)
known_hosts           = Add    (add unknown hosts to ~/.ssh/known_hosts)
```

**MAX output capture per command: 10 MB** (stdout/stderr each). Larger output is truncated to prevent OOM.

---

## ControlMaster Default Is OFF

Recent change: commit `464a25b` flipped the default to `control_master = false` because *stale local control sockets were poisoning otherwise healthy connections* — particularly painful for multi-agent fleets where one terminating session would orphan a master and the next agent would see hangs.

Opt-in if you really want connection reuse on a single-agent box:

```bash
export RCH_SSH_CONTROL_PERSIST_SECS=60       # enables persistence with 60s idle
```

If you opt in, expect to manually clean stale sockets occasionally:

```bash
ls /run/user/$(id -u)/openssh-* ~/.ssh/control-* ~/.ssh/cm-* "${TMPDIR:-/tmp}"/ssh-* 2>/dev/null   # /run/user is Linux-only
ssh -O check ubuntu@<host> 2>&1 || true
ssh -O exit ubuntu@<host> 2>&1 || true
```

A symptom signature for ControlMaster poisoning: probes succeed (`rch workers probe --all`), but `rch exec -- ...` hangs at "syncing" or "executing" with no progress for ~30s before failing.

---

## Keepalives for Long Builds

`cargo build --release` for a big workspace can sit idle on the SSH channel while the worker does heavy CPU work and emit nothing for minutes. NAT/firewall idle timers can drop the connection.

```bash
export RCH_SSH_SERVER_ALIVE_INTERVAL_SECS=15
```

This sets `ServerAliveInterval=15`, equivalent to a heartbeat every 15 seconds. Symptom this fixes: `RCH-E105 SSH session terminated unexpectedly` mid-build with no other apparent cause.

---

## Connect / Command Timeouts

Connect: 10s default. Command: 300s default. The command timeout is the upper bound on a single SSH command (probe, mkdir, exec wrapper). A real *build* runs through the workers' own pipeline and is bounded by `[compilation] build_timeout_sec`, not the SSH command timeout.

To raise across the board, set `[compilation] build_timeout_sec = 1800` for a 30-minute ceiling.

For ad-hoc one-shot tuning of the daemon's own SSH command timeouts, you'll need to edit the source — there's no env knob today. (If you find yourself wanting one, that's a code change worth filing.)

---

## Authentication Failure Triage

`RCH-E101 SSH authentication failed` is almost always one of:

1. Wrong key in workers config: read the worker's `identity_file` in `~/.config/rch/workers.toml` (`rch config edit --workers`; `rch --json workers list` does not include it) and run `rch config doctor`, which flags missing/unresolvable keys.
2. Permissions on the key: `chmod 600 ~/.ssh/<key>`.
3. Agent doesn't have the key: `ssh-add ~/.ssh/<key>` (if you use ssh-agent).
4. Key not authorized on the worker: `ssh -i <key> ubuntu@<host> true` reproduces.

`RCH-E102 SSH key not found or invalid format` — the path in `identity_file` doesn't exist or isn't a private key. Check `ls -la <path>` and `head -1 <path>` (PEM vs OpenSSH).

`RCH-E103 SSH host key verification failed` — the worker's host key changed (rebuild?). Compare the new fingerprint with what's stored:

```bash
ssh-keygen -F <host>             # what we know
ssh-keyscan <host> 2>/dev/null   # what the host claims now
```

If you trust the new fingerprint, remove the old entry (with explicit user authorization) and let `KnownHostsPolicy::Add` re-add on next probe.

---

## Retryable vs Fatal Transport Errors

`is_retryable_transport_error_text` (in `rch-common/src/ssh_utils.rs`) classifies SSH errors by substring. Retryable:

- `connection reset`, `broken pipe`, `connection refused`, `connection unexpectedly closed`, `connection lost`
- `no route to host`, `network is unreachable`, `temporary failure in name resolution` (the full phrase)
- `ssh_exchange_identification`, `control socket` (stale ControlMaster sockets)
- a bare `no such file or directory` is deliberately kept **out of the fatal list** (openssh emits it for a transient stale ControlMaster socket) — but it is not in the retryable list either, so on its own it classifies as non-retryable

Fatal (never retried):

- `permission denied`, `identity file`, `keyfile`, `invalid format` (auth/key problems)
- `host key verification failed`
- `could not resolve hostname`, `unknown option`

The daemon retries retryable errors with backoff. If you keep seeing the same error on retry, treat it as fatal and triage with `rch workers probe <id>` and direct `ssh -v`.

---

## Known-Hosts Policy

Three modes (`rch_common::ssh::KnownHostsPolicy`):

- `Strict` — production-style, fails closed on unknown
- `Add` (default) — auto-adds first time
- `AcceptAll` — testing only

There's no env override today; this is set by the daemon's SSH session builder. If you want strict, you'd have to use a wrapper. For most agent fleets, `Add` is fine.

---

## End-to-End Probe Recipes

Single worker:

```bash
rch workers probe <worker-id> --json
ssh -v -i <identity_file> ubuntu@<host> 'echo OK; df -h / /tmp; free -h'
```

All workers, parallel:

```bash
rch --json workers probe --all | jq '.data.results[] | {id, status, latency_ms, error_code, error}'
```

If a probe says ok but `rch exec` fails:

```bash
RCH_LOG_LEVEL=debug RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --quiet 2>&1 | tail -50
```

Look for the first SSH-shaped error in that tail. The structured remediation field of `RCH-E1xx` codes will point you to the right knob.

---

## Multi-Hop / Jump Host

If your workers sit behind a bastion, set it in `~/.ssh/config` and refer to the alias as the worker `host`:

```sshconfig
Host worker-a
  HostName 10.0.0.5
  User ubuntu
  ProxyJump bastion.example.com
  IdentityFile ~/.ssh/id_ed25519_workers
```

Then `[[workers]]` uses `host = "worker-a"`. Alias-based path topology resolution was fixed back in the v1.0.11 line, so multi-hop aliases work cleanly on any current release.

---

## Quick Knob Cheat Sheet

| Knob | Purpose |
|---|---|
| `RCH_SSH_SERVER_ALIVE_INTERVAL_SECS` | Keepalive interval for long-running commands (`[transfer] ssh_server_alive_interval_secs`) |
| `RCH_SSH_CONTROL_PERSIST_SECS` | Enable ControlMaster + persist N idle seconds. `0` = disable. |
| `RCH_COMPRESSION_LEVEL` | Transfer compression level (default 3). `RCH_TRANSFER_ZSTD_LEVEL` is **not** read — it only triggers a validator warning |
| `RCH_SYNC_TIMEOUT_MS` | Per-attempt source-upload timeout (default payload-aware) |
| `[transfer.retry]` | `max_attempts 3`, `base_delay_ms 100`, `max_delay_ms 5000`, `jitter_factor 0.1`, `total_timeout_ms 30000` |
| `[fleet] ssh_connect_timeout_secs / ssh_command_timeout_secs` | SSH budgets for fleet operations (10 s / 30 s) |
| `[[workers]] identity_file` | Per-worker key path (no `RCH_SSH_KEY` override exists — that name only produces validation warnings) |
| `[[workers]] priority` | Selection bias among equally eligible workers |
| `[[workers]] tags` | Descriptive only — **not** a selection filter (the one exception is the reserved `os:<name>` tag that `os = "…"` is normalized into, which *is* a hard gate) |

Transfer transport: rsync over SSH on Unix workers; **tar-over-ssh** on
`os = "windows"` workers (bounded by a transfer timeout, stderr drained
concurrently since v1.0.56).
