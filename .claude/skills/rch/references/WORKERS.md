# Worker Management

## Contents

- [Worker Lifecycle](#worker-lifecycle)
- [Add a Worker Manually](#add-a-worker-manually)
- [Drain / Disable / Enable](#drain--disable--enable)
- [Toolchain and Binary Management](#toolchain-and-binary-management)
- [Fleet-Level Rollout Commands](#fleet-level-rollout-commands)
- [Cross-Platform Workers (`os =`)](#cross-platform-workers-os-)
- [Worker Selection Notes](#worker-selection-notes)
- [SSH Verification Shortcuts](#ssh-verification-shortcuts)

## Worker Lifecycle

### 1) Discover and add workers

```bash
rch workers discover
rch workers discover --probe
rch workers discover --add --yes
```

### 2) Complete setup

```bash
rch workers setup --all
```

This performs the standard bootstrap path (binary/toolchain setup, validation) for configured workers.

### 3) Validate runtime health

```bash
rch workers list --speedscore
rch workers probe --all
rch workers capabilities --refresh
rch check
```

---

## Add a Worker Manually

Edit `~/.config/rch/workers.toml`:

```toml
[[workers]]
id = "new-worker"
host = "203.0.113.20"
user = "ubuntu"
identity_file = "~/.ssh/new_worker_ed25519"
total_slots = 16
priority = 90
tags = ["rust", "bun"]
```

Then validate and setup:

```bash
rch config validate
rch workers probe new-worker
rch workers setup new-worker
```

---

## Drain / Disable / Enable

Use these for maintenance windows and incident isolation.

```bash
rch workers drain <worker> -y
rch workers disable <worker> --reason "maintenance" --drain -y
rch workers enable <worker>
```

State model:

- `HEALTHY`: accepting jobs
- `DRAINING`: finishing active jobs, no new jobs
- `DRAINED`: idle and not accepting jobs
- `DISABLED`: explicitly offline from scheduler

---

## Toolchain and Binary Management

```bash
rch workers sync-toolchain --all
rch workers deploy-binary --all
```

Use `--dry-run` before broad changes:

```bash
rch workers sync-toolchain --all --dry-run
rch workers deploy-binary --all --dry-run
```

---

## Fleet-Level Rollout Commands

```bash
rch fleet status
rch fleet deploy --verify
rch fleet deploy --canary 25 --canary-wait 60 --verify
rch fleet rollback --verify
rch fleet history --limit 20
```

---

## Cross-Platform Workers (`os =`)

A worker whose host OS differs from the rest of the fleet — a Windows box for
`*-pc-windows-msvc` builds, say — must declare it:

```toml
[[workers]]
id = "win1"
host = "<tailscale-ip-or-hostname>"
user = "<ssh-user>"
identity_file = "~/.ssh/<key>"
total_slots = 4
priority = 60
os = "windows"          # linux | darwin | windows
tags = ["rust"]
```

`os` is a **hard admission gate**, unlike `tags`, which are descriptive and gate
nothing. Declaring it makes the worker **exclusive**: it accepts only commands
that require that OS, so an ordinary `cargo check` dispatched from a Linux or
macOS orchestrator can never land there and hand back wrong-platform artifacts.
A worker with no `os` set keeps taking anything — which is why every existing
worker is unaffected.

The requirement is derived from the command's `--target` triple:

| Triple | Requires | Why |
|---|---|---|
| `*-pc-windows-msvc` | `os = "windows"` | links against the MSVC toolchain |
| `*-apple-*` (darwin/ios/tvos/watchos) | `os = "darwin"` | needs the macOS SDK |
| `*-pc-windows-gnu`, `wasm32-*`, everything else | nothing | cross-compiles fine from Linux |

Consequences worth knowing:

- A `--target x86_64-pc-windows-msvc` build with **no** `os = "windows"` worker in
  the fleet finds nothing admissible and falls back to **local** — better than the
  old behaviour of shipping it to a Linux worker to fail.
- `rch status` diagnostics report the exclusion as reason code
  `os.declared_mismatch`, so you can tell it apart from a busy or unhealthy worker.

> **Deploy order matters.** `WorkerEntry` does not use
> `#[serde(deny_unknown_fields)]`, so an rchd built *before* this gate existed
> parses `os = "windows"`, silently discards it, and treats the machine as an
> ordinary worker that accepts every Linux job. **Roll rchd out to the whole
> fleet first, then add the worker** — the reverse order fails silently.

### Windows worker offload (setup + transport)

A Windows worker builds under **`C:/rch`** (drive letter + forward slashes — Git's
POSIX `sh` and `cargo.exe` both accept that form) and syncs over **tar-over-ssh**,
not rsync. Every bit of this is gated on the worker's declared `os = "windows"`,
so the Linux/macOS fleet paths stay byte-identical.

One-time setup on the Windows box (rch 1.0.54+):

1. Install Git for Windows, the Rust toolchain(s) you build with, and the MSVC
   build tools (so `link.exe` exists for `*-pc-windows-msvc`).
2. Point sshd at Git bash so the daemon's raw POSIX probes parse (cmd.exe mangles
   quotes): set the `DefaultShell` registry value under `HKLM:\SOFTWARE\OpenSSH`
   to `C:\Program Files\Git\bin\bash.exe`.
3. Append `C:\Program Files\Git\usr\bin` to the **machine** PATH — this supplies a
   native `tar` for the transport.
4. Set machine env `RCH_WKR_CANONICAL_ROOT=C:/rch` and `RCH_WKR_ALIAS_ROOT=C:/rch`.
   Without them the worker reports `projects_root_ok:false` and the daemon's
   topology preflight excludes it (Windows has no `/data/projects` alias-symlink
   topology — that check is a no-op there by design).
5. Build `rch-wkr` **natively** on the box and put it on PATH (e.g.
   `~/.local/bin/rch-wkr.exe`). Cross-compiling it from macOS/Linux fails at MSVC
   build scripts. Rebuild it on each rch release.
6. Install every toolchain your projects pin (`rustup toolchain install <pinned>`).
   The daemon's toolchain preflight requires the *exact* toolchain the client
   sends, or the worker is excluded with `toolchain_preflight_command_failed`.

Then add the worker with `os = "windows"` (after the fleet-wide rchd rollout) and
run a `cargo build --release --target x86_64-pc-windows-msvc`; the native `.exe`
is retrieved back into the local `target/`.

**v1 limitations, worth stating up front:**

- Best for **standalone crates / self-contained workspaces**. Multi-root
  path-dependency closures across sibling repos are not remapped under `C:/rch`
  (nor is clean-overlay / git-archive mode), so those fall back to local.
- Worker telemetry is a permanent **fail-open TelemetryGap** — the `/proc`-based
  collectors don't run on Windows, so `rch-wkr telemetry` returns nothing.
  Selection still works (the gap is a soft penalty; disk-free comes from the
  capabilities probe), but expect a steady `/proc/stat` warning in daemon logs.
- No in-session watchdog / process-group cancellation for Windows builds. The SSH
  ConnectTimeout, the per-command timeout, and the daemon stuck-detector still
  bound runaways.

---

## Worker Selection Notes

Selection favors availability and execution quality signals (slot capacity, health, and policy strategy).

Operational guidance:

- Keep `total_slots` realistic for CPU and memory limits.
- Prefer explicit `priority` shaping for known fast/reliable workers.
- Drain before disruptive operations.
- Keep worker toolchains synchronized to avoid fallback churn.
- Set `os` only on genuinely cross-platform workers; it fences them off from
  everything else.

---

## SSH Verification Shortcuts

Single worker:

```bash
rch workers probe <worker>
```

All workers with machine-readable output:

```bash
rch --json workers probe --all
```

If probes fail:

1. Verify `identity_file` exists and permissions are restrictive.
2. Verify worker host reachability and SSH service.
3. Re-run `rch workers setup <worker>` after connectivity is restored.
