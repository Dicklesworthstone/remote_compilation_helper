# Shared endpoint ownership and restart

The edge listener and every admitted connection share one endpoint owner. A
permanent `.rabs-<socket-name>.endpoint.lock` beside the socket is acquired
nonblocking before probing or binding. It is separate from cargo-rabs's inherited
startup locks and from CAS mount ownership: different state directories cannot
start participating daemons over the same endpoint. Parent aliases converge on
the actual parent inode. Only the last listener/session owner retires the bound
socket generation and releases the lock, after session-owned blocking work has
been joined. The lock file itself is retained.

Startup observes the final directory entry without following a symlink. Only an
unchanged, same-user, single-link, mode-0600 socket with an actual
`ConnectionRefused` probe result is eligible for retirement. A bounded probe
that times out, lacks permission, encounters a different socket protocol, or
observes a replacement refuses startup without removing the entry. Ordinary
files, links, unknown owners and malformed lock metadata are not repaired.

The runtime adapter uses `UnixListener::from_std` rather than automatic listener
pathname cleanup. Final retirement verifies the original socket generation and
held directory/lock identities. Chmod and unlink are descriptor-relative. A
replaced socket, parent or lock is left alone and logged, not silently repaired.
An unrelated failure during startup cannot authorize unconditional cleanup.

## Operational boundary

Use a same-user parent directory that is not writable by group or others. Newly
created parents use mode 0700. A socket directly under shared `/tmp` now refuses
startup; a private directory beneath `/tmp` is appropriate. Existing directories
are not chmodded. A crash between initial bind and permission establishment may
leave an unsafe socket that requires diagnosis rather than automatic takeover.

These are cooperative, local-host fences, not protection against hostile code
with the same UID or a cross-host coordinator election. Old daemons that do not
participate in the endpoint lock cannot be retroactively fenced. A live legacy
listener is nevertheless preserved by the liveness probe. Never remove the
permanent lock file as routine cleanup.

Filesystem calls are not claimed cancellable. An admitted connection, a joined
writer, or blocked kernel I/O may delay ownership release and a subsequent
restart. No serving policy, input key, execution retry, artifact publication or
compiler-skip authority changes. This does not implement canonical-worker action
dispatch or establish Cargo speedup.

## Qualification

Thirteen sandbox regressions exercise real local socket/filesystem/lock APIs;
six adapter regressions cover bound listeners, surviving session ownership,
legacy/dead sockets, wrong protocol, and preservation of replacement endpoints.
The adapter ownership test clones the same guard as the connection handler; it
is not a full daemon/Cargo integration test. The existing `edge::server` CI
selection includes the adapter tests; the sandbox selection is added explicitly.

```sh
rch exec -- cargo test -p rabs-sandbox --lib socket_endpoint --locked
rch exec -- cargo test -p rabsd --lib edge::server --locked
```

These Rust tests have not been run in the authoring environment. Twelve separate
Linux kernel primitive probes passed, but they do not execute the Rust patch or
prove its cancellation/drop ordering. Compilation, formatting, both backend
platforms and a controlled running-daemon restart still require qualification.
