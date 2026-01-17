# Build Sequence Diagram

## Standard Build Flow

This diagram shows the complete flow when an AI agent executes a compilation command.

```
┌─────────┐  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────┐
│ Agent   │  │   Hook   │  │   Daemon   │  │  Worker  │  │ rch-wkr  │
│         │  │  (rch)   │  │  (rchd)    │  │   SSH    │  │          │
└────┬────┘  └────┬─────┘  └─────┬──────┘  └────┬─────┘  └────┬─────┘
     │            │              │              │              │
     │ cargo build --release     │              │              │
     │────────────▶              │              │              │
     │            │              │              │              │
     │      Parse HookInput      │              │              │
     │      from stdin JSON      │              │              │
     │            │              │              │              │
     │      ┌─────┴─────┐        │              │              │
     │      │ Classify  │        │              │              │
     │      │ (5-tier)  │        │              │              │
     │      │ < 5ms     │        │              │              │
     │      └─────┬─────┘        │              │              │
     │            │              │              │              │
     │            │ GET /select-worker?project=X│              │
     │            │──────────────▶              │              │
     │            │              │              │              │
     │            │        ┌─────┴─────┐        │              │
     │            │        │ Selection │        │              │
     │            │        │ Algorithm │        │              │
     │            │        │           │        │              │
     │            │        │ Score:    │        │              │
     │            │        │ • Slots   │        │              │
     │            │        │ • Speed   │        │              │
     │            │        │ • Cache   │        │              │
     │            │        └─────┬─────┘        │              │
     │            │              │              │              │
     │            │◀─────────────┤ SelectedWorker               │
     │            │  {id: "css", slots: 12}     │              │
     │            │              │              │              │
     │            │              │              │              │
     │      ┌─────┴─────┐        │              │              │
     │      │  rsync    │        │              │              │
     │      │  project  │        │              │              │
     │      │  → worker │────────│──────────────▶              │
     │      │           │        │              │              │
     │      │ Exclude:  │        │       ┌──────┴──────┐       │
     │      │ target/   │        │       │  Receive    │       │
     │      │ .git/     │        │       │  project    │       │
     │      │ node_mod/ │        │       │  files      │       │
     │      └─────┬─────┘        │       └──────┬──────┘       │
     │            │              │              │              │
     │            │              │              │              │
     │            │ SSH: rch-wkr execute        │              │
     │            │──────────────│──────────────│──────────────▶
     │            │              │              │              │
     │            │              │              │     ┌────────┴────────┐
     │            │              │              │     │ Execute command │
     │            │              │              │     │                 │
     │            │              │              │     │ cargo build     │
     │            │              │              │     │ --release       │
     │            │              │              │     │                 │
     │            │              │              │     │ Stream stdout/  │
     │            │              │              │     │ stderr back     │
     │            │              │              │     └────────┬────────┘
     │            │              │              │              │
     │            │◀─────────────│──────────────│──────────────┤
     │            │  (streaming output)        │              │
     │            │              │              │              │
     │      ┌─────┴─────┐        │              │              │
     │      │  rsync    │        │              │              │
     │      │ artifacts │        │              │              │
     │      │ ← worker  │◀───────│──────────────┤              │
     │      │           │        │              │              │
     │      │ Include:  │        │              │              │
     │      │ target/   │        │              │              │
     │      │ release/  │        │              │              │
     │      └─────┬─────┘        │              │              │
     │            │              │              │              │
     │            │ POST /release-worker        │              │
     │            │──────────────▶              │              │
     │            │              │              │              │
     │            │       Release slots         │              │
     │            │              │              │              │
     │            │◀─────────────┤              │              │
     │            │  {released: true}           │              │
     │            │              │              │              │
     │◀───────────┤              │              │              │
     │  HookOutput: {}           │              │              │
     │  (silent allow)           │              │              │
     │            │              │              │              │
     │  Agent continues          │              │              │
     │  unaware of remote        │              │              │
     │  execution                │              │              │
     │            │              │              │              │
```

## Classification Timeline

Detail of the 5-tier classification happening in < 5ms:

```
Time (μs)    Operation
─────────────────────────────────────────────────────────────────
    0        Command received: "cargo build --release"
    │
    1        ┌───────────────────────────────────────────────┐
             │ Tier 0: Instant Reject Check                  │
             │ • Is this a Bash tool invocation? ✓           │
             │ • Has command content? ✓                      │
             └───────────────────────────────────────────────┘
             PASS → continue
    │
   10        ┌───────────────────────────────────────────────┐
             │ Tier 1: Structure Analysis                    │
             │ • Contains pipe (|)? ✗                        │
             │ • Contains background (&)? ✗                  │
             │ • Contains redirect (>, <, >>)? ✗             │
             │ • Contains chain (&&, ||, ;)? ✗               │
             │ • Contains subshell ($())? ✗                  │
             └───────────────────────────────────────────────┘
             PASS → continue (simple command)
    │
  100        ┌───────────────────────────────────────────────┐
             │ Tier 2: SIMD Keyword Filter (memchr)          │
             │ • Contains "cargo"? ✓                         │
             │ • Keywords: cargo, rustc, gcc, g++, clang,    │
             │   make, cmake, ninja, meson, bun              │
             └───────────────────────────────────────────────┘
             MATCH → continue (likely compilation)
    │
  500        ┌───────────────────────────────────────────────┐
             │ Tier 3: Negative Pattern Check                │
             │ • "cargo install"? ✗                          │
             │ • "cargo fmt"? ✗                              │
             │ • "cargo fix"? ✗                              │
             │ • "cargo clean"? ✗                            │
             │ • "cargo publish"? ✗                          │
             │ • "cargo add/remove"? ✗                       │
             │ • "--help"/"--version"? ✗                     │
             └───────────────────────────────────────────────┘
             PASS → not a negative pattern
    │
 2000        ┌───────────────────────────────────────────────┐
             │ Tier 4: Full Classification                   │
             │ • Parse command structure                     │
             │ • Match against CompilationKind patterns      │
             │ • Pattern: "cargo build" → CargoBuild         │
             │ • Flags: --release → adds confidence          │
             │ • Compute confidence score: 0.95              │
             │ • Threshold: 0.85                             │
             │ • 0.95 >= 0.85 → INTERCEPT                    │
             └───────────────────────────────────────────────┘
             RESULT: Classification::Remote(CargoBuild, 0.95)
    │
 2500        Decision made: REMOTE EXECUTION
─────────────────────────────────────────────────────────────────
Total: ~2.5ms for compilation command
```

## Fallback Flow

When remote execution fails, RCH falls back to local execution:

```
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Agent   │  │   Hook   │  │  Daemon  │  │  Worker  │
└────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │            │              │              │
     │ cargo build│              │              │
     │───────────▶│              │              │
     │            │              │              │
     │      Classify → Remote    │              │
     │            │              │              │
     │            │ GET /select  │              │
     │            │─────────────▶│              │
     │            │              │              │
     │            │◀─────────────┤              │
     │            │ SelectedWorker: css        │
     │            │              │              │
     │            │ rsync →      │              │
     │            │──────────────│──────────────▶
     │            │              │              │
     │            │              │      ┌───────┴───────┐
     │            │              │      │ SSH timeout   │
     │            │              │      │ or error      │
     │            │              │      └───────┬───────┘
     │            │              │              │
     │            │◀─────────────│──────────────┤
     │            │  Error: Connection failed  │
     │            │              │              │
     │      ┌─────┴─────┐        │              │
     │      │ FALLBACK  │        │              │
     │      │           │        │              │
     │      │ Allow     │        │              │
     │      │ local     │        │              │
     │      │ execution │        │              │
     │      └─────┬─────┘        │              │
     │            │              │              │
     │◀───────────┤              │              │
     │ HookOutput: {}            │              │
     │ (allow - runs locally)    │              │
     │            │              │              │
     │ Build runs │              │              │
     │ locally on │              │              │
     │ workstation│              │              │
     │            │              │              │
```

## Canary Deployment Flow

When deploying with `rch fleet deploy --canary 25`:

```
┌──────────────┐     ┌─────────────┐
│ Fleet Deploy │     │  Workers    │
│  (canary)    │     │ [1,2,3,4]   │
└──────┬───────┘     └──────┬──────┘
       │                    │
       │  Phase 1: Canary   │
       │  (25% = 1 worker)  │
       │────────────────────▶
       │         │          │
       │    Deploy to       │
       │    Worker 1        │
       │         │          │
       │         │◀─────────┤
       │         │  Success │
       │                    │
       │  Wait 60s for      │
       │  health check      │
       │                    │
       │  Health OK?        │
       │  ┌────┴────┐       │
       │  │   Yes   │       │
       │  └────┬────┘       │
       │       │            │
       │  Phase 2: Full     │
       │  (remaining 75%)   │
       │────────────────────▶
       │         │          │
       │    Deploy to       │
       │    Workers 2,3,4   │
       │    (parallel)      │
       │         │          │
       │◀────────│──────────┤
       │   All complete     │
       │                    │
       ▼                    │
  Fleet deployed            │
  successfully              │
```

## Circuit Breaker States

State transitions for worker health:

```
                    ┌─────────────┐
                    │   Closed    │
                    │  (normal)   │
                    └──────┬──────┘
                           │
              Failures ≥ threshold
                           │
                           ▼
                    ┌─────────────┐
         ┌─────────│    Open     │─────────┐
         │         │  (failing)  │         │
         │         └──────┬──────┘         │
         │                │                │
         │     After recovery_timeout      │
         │                │                │
         │                ▼                │
         │         ┌─────────────┐         │
         │         │  Half-Open  │         │
         │         │  (probing)  │         │
         │         └──────┬──────┘         │
         │                │                │
    Probe fails    ┌──────┴──────┐    Probe succeeds
         │         │             │         │
         │         ▼             ▼         │
         │    Back to Open   Back to       │
         └────────────────   Closed ───────┘


State Behaviors:
─────────────────────────────────────────────────
Closed:     • Accept all requests
            • Track failures
            • Transition on threshold

Open:       • Reject all requests immediately
            • Selection skips this worker
            • Wait for recovery_timeout

Half-Open:  • Allow one probe request
            • Other requests still rejected
            • Success → Closed, Failure → Open

Circuit Breaker Config:
─────────────────────────────────────────────────
failure_threshold: 3      # failures before open
recovery_timeout: 30s     # time before half-open
success_threshold: 1      # successes to close
```
