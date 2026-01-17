# State Machine Diagrams

## Worker Status State Machine

Workers transition between health states based on connectivity and performance:

```
                                    ┌──────────────────┐
                                    │     HEALTHY      │
                                    │                  │
                                    │ • Accepts builds │
                                    │ • Full score     │
                                    │ • Primary target │
                                    └────────┬─────────┘
                                             │
                         ┌───────────────────┼───────────────────┐
                         │                   │                   │
              Response > 5000ms        SSH/health         Manual drain
                  (slow)           check fails 3x          command
                         │                   │                   │
                         ▼                   ▼                   ▼
              ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
              │    DEGRADED      │ │   UNREACHABLE    │ │    DRAINING      │
              │                  │ │                  │ │                  │
              │ • Accepts builds │ │ • No new builds  │ │ • No new builds  │
              │ • Score penalty  │ │ • Circuit opens  │ │ • Waits for      │
              │ • Less preferred │ │ • Probe retry    │ │   active builds  │
              └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
                       │                    │                    │
           Response < 2000ms      Probe succeeds       All builds complete
            (recovered)             3 times           or admin re-enables
                       │                    │                    │
                       └───────────┬────────┴────────────────────┘
                                   │
                                   ▼
                            Back to HEALTHY
                                   or
                            ┌──────────────────┐
                            │    DISABLED      │
                            │                  │
                            │ • Admin disabled │
                            │ • No selection   │
                            │ • Needs manual   │
                            │   re-enable      │
                            └──────────────────┘


State Transitions Summary:
─────────────────────────────────────────────────────────────────────────────
From        │ To          │ Trigger                    │ Auto/Manual
────────────┼─────────────┼────────────────────────────┼─────────────
HEALTHY     │ DEGRADED    │ Response > 5000ms          │ Auto
HEALTHY     │ UNREACHABLE │ 3 consecutive failures     │ Auto
HEALTHY     │ DRAINING    │ `rch fleet drain`          │ Manual
DEGRADED    │ HEALTHY     │ Response < 2000ms          │ Auto
DEGRADED    │ UNREACHABLE │ 3 consecutive failures     │ Auto
UNREACHABLE │ HEALTHY     │ 3 successful probes        │ Auto
DRAINING    │ HEALTHY     │ `rch fleet enable`         │ Manual
Any         │ DISABLED    │ `rch worker disable`       │ Manual
DISABLED    │ HEALTHY     │ `rch worker enable`        │ Manual
```

## Deployment Status State Machine

Per-worker deployment status during `rch fleet deploy`:

```
         ┌──────────────┐
         │   PENDING    │
         │              │
         │ Not started  │
         │ In queue     │
         └──────┬───────┘
                │
                │ Executor picks up
                │
                ▼
         ┌──────────────┐
         │  PREFLIGHT   │──────────────┐
         │              │              │
         │ SSH check    │        Preflight fails
         │ Disk check   │         (no SSH, disk)
         │ Tools check  │              │
         └──────┬───────┘              │
                │                      │
                │ All checks pass      │
                │                      │
                ▼                      │
         ┌──────────────┐              │
         │   DRAINING   │              │
         │   (optional) │              │
         │              │              │
         │ Wait for     │              │
         │ active builds│              │
         └──────┬───────┘              │
                │                      │
                │ Drained or skipped   │
                │                      │
                ▼                      │
         ┌──────────────┐              │
         │ TRANSFERRING │──────────────┤
         │              │              │
         │ rsync binary │        Transfer fails
         │ to worker    │         (network, ssh)
         └──────┬───────┘              │
                │                      │
                │ Transfer complete    │
                │                      │
                ▼                      │
         ┌──────────────┐              │
         │  INSTALLING  │──────────────┤
         │              │              │
         │ Install bin  │        Install fails
         │ Set perms    │         (perms, disk)
         │ Update PATH  │              │
         └──────┬───────┘              │
                │                      │
                │ Install complete     │
                │                      │
                ▼                      │
         ┌──────────────┐              │
         │  VERIFYING   │──────────────┤
         │              │              │
         │ Health check │        Verify fails
         │ Version chk  │         (bad install)
         │ Capability   │              │
         └──────┬───────┘              │
                │                      │
                │ All verified         │
                │                      │
                ▼                      ▼
         ┌──────────────┐       ┌──────────────┐
         │  COMPLETED   │       │    FAILED    │
         │              │       │              │
         │ Success!     │       │ Error logged │
         │ Worker ready │       │ Rollback?    │
         └──────────────┘       └──────┬───────┘
                                       │
                            Auto-rollback enabled?
                                       │
                              ┌────────┴────────┐
                              │                 │
                              ▼                 ▼
                       ┌──────────────┐  Continue to
                       │ ROLLED_BACK  │  other workers
                       │              │
                       │ Restored     │
                       │ previous ver │
                       └──────────────┘
```

## Build Job State Machine

State of a compilation job being processed:

```
                    ┌─────────────────┐
                    │    RECEIVED     │
                    │                 │
                    │ Hook got cmd    │
                    │ Classification  │
                    │ pending         │
                    └────────┬────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
        Classified as             Classified as
         REMOTE                    LOCAL
                │                         │
                ▼                         ▼
        ┌─────────────────┐       ┌─────────────────┐
        │    SELECTING    │       │     LOCAL       │
        │                 │       │                 │
        │ Query daemon    │       │ Pass-through    │
        │ for worker      │       │ to local shell  │
        └────────┬────────┘       └─────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
    Worker found      No workers
        │              available
        ▼                 │
┌─────────────────┐       │
│   TRANSFERRING  │       │
│                 │       │
│ rsync to worker │       │
└────────┬────────┘       │
         │                │
         │ Transfer OK    │ Transfer fails
         │                │
         ▼                ▼
┌─────────────────┐  ┌─────────────────┐
│   EXECUTING     │  │    FALLBACK     │
│                 │  │                 │
│ Running on      │  │ Run locally     │
│ worker          │  │ (fail-open)     │
└────────┬────────┘  └─────────────────┘
         │
┌────────┴────────┐
│                 │
│ Execution       │ Execution
│ succeeds        │ fails
│                 │
▼                 ▼
┌─────────────────┐  ┌─────────────────┐
│  COLLECTING     │  │  ERROR          │
│                 │  │                 │
│ rsync artifacts │  │ Report to       │
│ back            │  │ agent           │
└────────┬────────┘  └─────────────────┘
         │
         ▼
┌─────────────────┐
│   COMPLETED     │
│                 │
│ Artifacts in    │
│ local target/   │
│ Silent success  │
└─────────────────┘
```

## Daemon Lifecycle State Machine

States of the rchd daemon:

```
                ┌─────────────────┐
                │    STARTING     │
                │                 │
                │ Load config     │
                │ Parse workers   │
                │ Init SSH pool   │
                └────────┬────────┘
                         │
                         │ Initialization complete
                         │
                         ▼
                ┌─────────────────┐
                │  HEALTH_CHECK   │◀───────────┐
                │                 │            │
                │ Probe all       │            │
                │ workers         │            │
                │ Update states   │            │
                └────────┬────────┘            │
                         │                     │
                         │ Ready               │ Every 30s
                         │                     │
                         ▼                     │
              ┌─────────────────────┐          │
              │      RUNNING        │──────────┘
              │                     │
              │ Accept API requests │
              │ Handle builds       │
              │ Track statistics    │
              └──────────┬──────────┘
                         │
           ┌─────────────┼─────────────┐
           │             │             │
     SIGTERM/      API shutdown    Fatal error
     SIGINT         request
           │             │             │
           ▼             ▼             ▼
    ┌─────────────────────────────────────────┐
    │             SHUTTING_DOWN               │
    │                                         │
    │ • Stop accepting new requests           │
    │ • Wait for active builds (timeout)      │
    │ • Close SSH connections                 │
    │ • Write final statistics                │
    │ • Remove socket file                    │
    └────────────────────┬────────────────────┘
                         │
                         ▼
                ┌─────────────────┐
                │    STOPPED      │
                │                 │
                │ Process exits   │
                │ Clean shutdown  │
                └─────────────────┘
```

## Hook Decision Flow

Quick reference for hook classification decision:

```
                        ┌───────────────┐
                        │ Command Input │
                        └───────┬───────┘
                                │
                    ┌───────────┴───────────┐
                    │ Is Bash tool?         │
                    └───────────┬───────────┘
                          Yes   │   No
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
            ┌───────────────┐       ┌───────────────┐
            │ Continue      │       │ ALLOW (other) │
            └───────┬───────┘       └───────────────┘
                    │
        ┌───────────┴───────────┐
        │ Contains |, &, >, etc?│
        └───────────┬───────────┘
              No    │   Yes
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌───────────────┐       ┌───────────────┐
│ Continue      │       │ ALLOW (local) │
└───────┬───────┘       └───────────────┘
        │
┌───────┴───────────────┐
│ Contains build keyword│
│ (cargo, gcc, etc)?    │
└───────────┬───────────┘
      Yes   │   No
┌───────────┴───────────┐
│                       │
▼                       ▼
┌───────────────┐  ┌───────────────┐
│ Continue      │  │ ALLOW (local) │
└───────┬───────┘  └───────────────┘
        │
┌───────┴───────────────┐
│ Is negative pattern?  │
│ (fmt, install, etc)   │
└───────────┬───────────┘
      No    │   Yes
┌───────────┴───────────┐
│                       │
▼                       ▼
┌───────────────┐  ┌───────────────┐
│ INTERCEPT     │  │ ALLOW (local) │
│ Execute remote│  └───────────────┘
└───────────────┘


Decision Latency Targets:
───────────────────────────────────
ALLOW (other tool):    < 0.01ms
ALLOW (complex cmd):   < 0.1ms
ALLOW (not build):     < 0.2ms
ALLOW (neg pattern):   < 0.5ms
INTERCEPT decision:    < 5ms
```
