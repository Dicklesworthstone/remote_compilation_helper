# ADR-001: Unix Socket for Daemon IPC

## Status

Accepted

## Context

The RCH CLI (`rch`) needs to communicate with the daemon (`rchd`) for:
- Worker selection queries
- Slot reservation/release
- Status queries
- Shutdown commands

Options considered:
1. **Unix domain socket** (chosen)
2. TCP socket on localhost
3. Shared memory with futex
4. Named pipes (FIFO)
5. D-Bus / system message bus

## Decision

Use Unix domain sockets for all IPC between the hook and daemon.

**Protocol:** Simple HTTP-like text protocol over the socket:

```
GET /select-worker?project=myproject&cores=4&runtime=rust\n
```

Response:

```
HTTP/1.0 200 OK
Content-Type: application/json

{"worker": {...}, "reason": "success"}
```

**Socket path:** `$XDG_RUNTIME_DIR/rch.sock` (preferred) or `~/.cache/rch/rch.sock`
(configurable; falls back to `/tmp/rch.sock`)

## Consequences

### Positive

- **Zero network overhead**: No TCP/IP stack involvement
- **Built-in permissions**: File system permissions control access
- **Reliable delivery**: Stream socket guarantees ordering and delivery
- **Efficient for small messages**: No packet overhead
- **Simple implementation**: Standard socket APIs, no external dependencies
- **Debuggable**: Can use `socat` or `nc -U` for manual testing

### Negative

- **Not portable to Windows**: Windows uses named pipes (different API)
- **File system state**: Socket file must be managed (cleanup on crash)
- **Single-machine only**: Cannot communicate across network (by design)

### Mitigations

- Socket cleanup on daemon startup (remove stale socket files)
- Lock file to prevent multiple daemon instances
- Future: Windows support via named pipes with abstraction layer

## Alternatives Considered

### TCP Socket on Localhost

- **Pro**: Standard, portable, well-understood
- **Con**: Unnecessary network stack overhead
- **Con**: Port management (conflicts, firewall rules)
- **Con**: Weaker permission model (any local user can connect)

### Shared Memory with Futex

- **Pro**: Fastest possible IPC
- **Con**: Complex synchronization
- **Con**: Harder to debug
- **Con**: No built-in message framing

### Named Pipes (FIFO)

- **Pro**: Simple, file-based
- **Con**: Unidirectional (need two pipes)
- **Con**: No multiplexing

### D-Bus

- **Pro**: Rich type system, service discovery
- **Con**: Heavy dependency
- **Con**: Overkill for simple request/response

## References

- `rchd/src/api.rs` - Socket server implementation
- `rch/src/hook.rs` - Socket client implementation
