# Remote-agent admission preview client

`scripts/rch-admission-preview.py` is a Python 3.9+ client for the protected
`rchd` HTTP `/admission-preview` endpoint. It runs from this checkout; it is
not automatically installed and does not replace the Rust `rch admit` command.
The existing daemon API listener must already be configured. Nothing starts,
restarts or reconfigures a daemon.

This client supplies the exact versioned `PreviewRequest` implemented in
`rch-common/src/admission_preview.rs`. It neither classifies the command nor
infers execution requirements. The daemon owns worker selection, current
source exclusions, project-lane observations, maintenance barriers, tool
verification and capacity policy. Supply the same project identifier and
requirements that the eventual execution will use: a different project name
is not evidence that the real project's source exclusions are clear.

## One observation

Use an existing, same-user, private regular token file (mode `0600` or `0400`).
The token must match the daemon's configured API token. Never put credentials
in the endpoint URL or request JSON.

```sh
python3 scripts/rch-admission-preview.py \
  --endpoint http://100.64.0.10:9101 \
  --token-file "$HOME/.config/rch/api.token" <<'JSON'
{
  "protocol_version": 1,
  "project": "my-project",
  "command": "make test",
  "estimated_cores": 4,
  "disk_headroom_gib": 20,
  "preferred_workers": ["builder-a", "builder-b"],
  "required_runtime": "none",
  "job_mode": true,
  "required_tools": ["make", "cc"]
}
JSON
```

`--request request.json` reads a file instead of stdin. The request is bounded
at 65,536 UTF-8 bytes. The four required fields are `protocol_version`,
`project`, `command`, and `estimated_cores`. Other protocol defaults remain
unchanged; omitted fields are not replaced with inferred or weaker requirements.
`required_runtime` is `none`, `rust`, `bun`, `node`, `nix`, `go`, or `zig`.
For Rust requirements, `toolchain` accepts the existing `ToolchainInfo` shape
(`channel`, optional/null `date`, and `full_version`). Obtain that identity from
the execution environment; this client does not run rustc or guess its version.

The endpoint is an origin, with no username, password, path, query, or fragment.
The client always POSTs to `/admission-preview`. HTTPS retains system
certificate and hostname verification. Cleartext HTTP is limited to literal
loopback addresses and the daemon's Tailscale address ranges; a matching address
alone is **not** proof of an encrypted or trusted network. Use HTTPS or an
operator-established trusted tailnet. Hostnames require HTTPS. Proxy environment
variables are ignored and redirects are refused, so they cannot silently change
the recipient of the credential or the admission request.

`--no-token` must be explicit for a daemon deliberately configured with
`api.no_token = true`. No ambient token variable is read. Private-token-file
checks require POSIX facilities; Linux and macOS are the intended clients.

## Machine output and exit status

Every completed invocation emits one JSON document. The daemon's selection,
including its diagnostics and optional observed project lane, is retained:

```json
{
  "protocol_version": 1,
  "observation": "unavailable",
  "execution_authorized": false,
  "selection": {
    "worker": null,
    "reason": "all_workers_busy"
  }
}
```

| Exit | Observation | Meaning |
|---|---|---|
| `0` | `available` | The daemon observed an in-set worker with enough reported slots. |
| `1` | `unavailable` | The daemon returned a recognized selection denial; inspect its reason and diagnostics. |
| `2` | `unknown` | Input, protocol, authentication, transport, timeout, internal selection error, or inconsistent evidence prevented a reliable observation. |

`selection_error` is unknown even when the HTTP response is valid. A `429`
means the preview service is saturated, not that worker slots are exhausted.
Missing daemons, malformed responses, unknown protocol variants, a selected
worker outside the requested set, and responses carrying any build ID all
produce unknown. The client never tries to release an unexpected build ID.

An available result is **not execution authority**. Another build can consume
the observed slots or lane immediately. Repeated requests can all observe the
same capacity because none reserves it. Start work only through the ordinary
RCH execution/admission path. This client does not queue, retry, choose a local
fallback, transfer project files, or execute the supplied command. Do not turn
an unknown observation into permission to build locally.

## Bounds and cancellation

`--timeout` defaults to three seconds and accepts `0.05..30`. After local input
and token validation, one deadline covers helper startup, DNS, TCP connection,
TLS, response headers and the response body. Successful partial reads do not
renew it. The client uses a directly owned, isolated Python helper for network
I/O; expiry or a caught parent-side exception kills and reaps that helper. A
separate, inherited ownership pipe also makes the helper exit and close its
connection if the parent dies abruptly. It does
not signal a daemon, a worker, a process group or an arbitrary recorded PID.
Kernel scheduling and local input-file reads are not claimed to be hard-real-time.

Responses are limited to one MiB of uncompressed body bytes. Content decoding,
ambiguous framing, duplicate JSON fields, non-finite JSON numbers and truncated
bodies are refused. Error responses are not echoed, and a reflected credential
in a successful response is refused rather than printed. TLS verification cannot
be disabled by a command-line option. No temporary credential or request file
is written by the client.

## Validation

```sh
python3 scripts/tests/test_admission_preview_client.py
```

The native tests run the real executable and transport subprocess against
owned HTTP/TLS peers, with explicit protocol fixtures. They exercise exact
request transmission, lane and pin handling, denial-versus-unknown semantics,
old and malformed replies, cancellation/reaping, trickled headers/body,
redirect/proxy isolation, private credentials and certificate verification.
They do not launch Rust binaries and are not live-daemon or fleet qualification.
