# RABS Unsafe-Boundary Ledger

**Bead:** `rabs-root-4pidu.19.11` (A011) · **Consumer:** the S010 release
gate (a release may not ship while this ledger is stale) and privileged-code
reviewers · **Gates:** any change to a privileged helper · **Retirement:**
never while RABS ships privileged helpers; retire only if the last helper is
removed.

Every RABS component that crosses a privilege or safety boundary —
sandbox/mount-namespace helpers, chroot/VM launchers, seccomp/Landlock
shims, raw-socket/QUIC internals adopted from Asupersync — must have an
entry here **in the same change that introduces or modifies it**. The
`ledger_is_current` test in `rabs-sandbox/tests/unsafe_boundary_ledger.rs`
fails when a known privileged-helper location exists without a matching
ledger entry.

All RABS library crates forbid `unsafe_code` at the manifest level; a
privileged operation therefore lives in a **separate, audited, bounded
helper binary** — never inline in a library (see `rabs-sandbox`'s crate
doc). This ledger is the audit trail for those helpers.

## Entry contract (every entry answers all six)

1. **What boundary it crosses** (root privilege, mount namespace, device
   access, raw sockets, …) and why a helper is unavoidable.
2. **Protocol bounds**: exact request surface, size/recursion limits,
   path-safety rules (no `..`, no symlink following into caller-controlled
   space), refusal behavior.
3. **Blast radius if compromised**, and what contains it.
4. **Fuzz status**: which fuzz target covers the request surface, or the
   dated reason none does yet (a debt item, not a shrug).
5. **Review record**: last reviewer + date + revision.
6. **Deletion condition**: what change makes the helper unnecessary.

## Entries

### 1. `rabs-macos-root-helper` (Bead D013 — macOS Canonical Process Root via Chroot / Virtualization.framework VM)

- **What boundary it crosses**: Root privilege (`chroot(2)` / sandbox container setup over per-action APFS `clonefile(2)` staging directories) or `com.apple.security.virtualization` (`Virtualization.framework` lightweight guest root mount). APFS clones alone provide copy-on-write data blocks without giving concurrent processes the same canonical visible absolute path (`/rabs/execroot/ws`, `/rabs/execroot/target`, `/rabs/execroot/cargo-home`, `/rabs/execroot/toolchain`, `/rabs/execroot/tmp`, `/rabs/execroot/out` — risk R47); a privileged chroot or VM boundary is therefore unavoidable on macOS for `StrictHermeticVm`.
- **Protocol bounds**: Accepts a single bounded `MacOsRootLaunchRequest` (`<= 16 KiB`), maximum 8 mount bindings (`ws`, `target`, `cargo-home`, `toolchain`, `tmp`, `out`), strict path-safety validation (no relative paths, no `..` traversal components, `O_NOFOLLOW` verification that no staging component resolves a symlink into caller-controlled space outside the daemon-owned `/private/var/rabs/stage` root). Refuses with `MacOsRootHelperRefusal` and drops privileges to the unprivileged build UID/GID before `execve`.
- **Blast radius if compromised**: Contained to the daemon-owned staging dataset (`/private/var/rabs/stage/<action-id>`) and the unprivileged build UID/GID; the helper holds no coordinator signing keys, no CAS database handles, and no network sockets.
- **Fuzz status**: Request parser and path-safety validator covered by `rabs_protocol::authority_matrix::validate_macos_root_helper_request` deterministic property/mutation tests and the T003 path-canonicalization fuzz target.
- **Review record**: Reviewed by RABS Security & Sandbox audit pass · 2026-10-19 · revision `v1` (bead D013).
- **Deletion condition**: Delete if macOS introduces unprivileged user/mount namespaces with per-process filesystem root remapping equivalent to Linux `CLONE_NEWUSER | CLONE_NEWNS`, or if Darwin worker support is retired.

### 2. `rabs-macos-es-observer` (Bead E017 — macOS Endpoint Security / VM-Mediated Observation Helper)

- **What boundary it crosses**: Privileged `EndpointSecurity.framework` (`com.apple.developer.endpoint-security.client` entitlement subscribing to `ES_EVENT_TYPE_NOTIFY_OPEN`, `EXEC`, `LOOKUP`, `STAT`, `READLINK`, and network connect events) or `Virtualization.framework` virtiofs hypervisor read/exec/network mediation. Unprivileged `FSEvents` observes directory/file mutations only — never reads or failed open lookups — and is explicitly restricted to edit/speculation watching (`NO_CLAIM_MACOS_FSEVENTS_READ_OBSERVATION`).
- **Protocol bounds**: Streams bounded observation records (`<= 64 KiB` frame batch) over a local root-owned UNIX domain socket to the worker attempt supervisor; tracks kernel ring-buffer sequence numbers and immediately marks any attempt with `dropped_events > 0` as non-authoritative (`ShadowOnly`).
- **Blast radius if compromised**: Read-only observation stream for child PIDs inside the active action process group; cannot mutate CAS objects, forge coordinator commit authority (R50), or elevate `HostSandboxAudit` beyond `SelectedImmutableClassesOnly`.
- **Fuzz status**: Event-frame decoder and soundness-boundary classifier covered by `rabs_protocol::authority_matrix::evaluate_macos_observation_soundness` unit/differential tests (beads D021/E017) and T003 codec fuzzing.
- **Review record**: Reviewed by RABS Security & Sandbox audit pass · 2026-10-19 · revision `v1` (bead E017).
- **Deletion condition**: Delete if Darwin actions execute exclusively inside `Virtualization.framework` guests where virtiofs mediates all filesystem reads without host Endpoint Security.

### Expected future entrants

| Expected helper | Beads | Boundary it will cross |
|---|---|---|
| Linux canonical-namespace helper | D003 | mount/user/pid namespaces, bind mounts, cgroup v2 setup |
| macOS chroot/VM root helper | D013 | privileged chroot or Virtualization.framework root *(ledgered above)* |
| seccomp/Landlock policy shim | D003/E005 | syscall filtering installed pre-exec |
| observation tracer (eBPF/fanotify/ES) | E005/E017 | kernel tracing facilities *(macOS ES/VM ledgered above)* |

Adding any of these without a ledger entry fails the ledger-currency test.

## Change log

- 2026-08-06 — Ledger created with zero entries (no privileged code exists
  yet); currency test wired in `rabs-sandbox` (bead A011).
- 2026-10-19 — Added six-field ledger entries for `rabs-macos-root-helper`
  (bead D013) and `rabs-macos-es-observer` (bead E017), recording the
  APFS-clone path-identity constraint (risk R47) and the `FSEvents`
  mutation-only non-claim boundary.
