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

*(none yet — deliberately)*

No privileged helper exists in the RABS tree at ledger creation time
(2026-08-06). The first expected entrants, from the plan:

| Expected helper | Beads | Boundary it will cross |
|---|---|---|
| Linux canonical-namespace helper | D003 | mount/user/pid namespaces, bind mounts, cgroup v2 setup |
| macOS chroot/VM root helper | D013 | privileged chroot or Virtualization.framework root |
| seccomp/Landlock policy shim | D003/E005 | syscall filtering installed pre-exec |
| observation tracer (eBPF/fanotify/ES) | E005/E017 | kernel tracing facilities |

Adding any of these without a ledger entry fails the ledger-currency test.

## Change log

- 2026-08-06 — Ledger created with zero entries (no privileged code exists
  yet); currency test wired in `rabs-sandbox` (bead A011).
