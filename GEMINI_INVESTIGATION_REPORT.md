# Gemini Investigation Report

**Date:** Monday, January 26, 2026
**Agent:** Gemini CLI

## Overview
This report summarizes the findings from the initial codebase investigation of the Remote Compilation Helper (RCH) project.

## Codebase Structure
The project is a Rust workspace with the following members:
- **`rch`**: The client-side hook that integrates with Claude Code. It handles command classification and orchestrates the offloading process.
- **`rchd`**: The background daemon that manages the worker fleet, tracks slot usage, and selects the best worker for a job.
- **`rch-wkr`**: The worker binary that runs on remote machines (though much of the logic seems to be standard SSH/rsync usage).
- **`rch-common`**: Shared types, protocols, and the command classification logic.

## Key Components Status

### 1. Command Classification (`rch-common/src/patterns.rs`)
- **Status:** Implemented.
- **Details:** A 5-tier classification system is in place. It correctly identifies `cargo`, `rustc`, `gcc`, `make`, etc., and excludes commands like `cargo install`.
- **Ref:** `classify_command` function.

### 2. Worker Selection (`rchd/src/selection.rs`)
- **Status:** Implemented.
- **Details:** The `WorkerSelector` implements multiple strategies (`Priority`, `Fastest`, `Balanced`). It considers speed, slots, health, and cache affinity.
- **Ref:** `WorkerSelector::select` and `handle_select_worker` in `api.rs`.

### 3. Transfer Pipeline (`rch/src/transfer.rs`)
- **Status:** Implemented.
- **Details:** Uses `rsync` with `zstd` compression. Handles syncing source code to the worker and retrieving artifacts. Supports streaming output.
- **Ref:** `TransferPipeline` struct.

### 4. Hook Logic (`rch/src/hook.rs`)
- **Status:** Implemented.
- **Details:** Reads JSON input, classifies, queries `rchd`, executes remote compilation, and handles output/errors.

## Missing Features / Discrepancies

### Compilation Deduplication
- **Claim:** The `README.md` states: "RCH deduplicates these using broadcast channels... `rchd` maintains `InFlightCompilations` map."
- **Reality:** I found no evidence of `InFlightCompilations` or broadcast channels in `rchd/src/main.rs`, `rchd/src/api.rs`, or `rchd/src/selection.rs`.
- **Observation:** `rch` connects directly to the worker via SSH (`SshClient`). The daemon is only consulted for worker selection and slot reservation. Unless the daemon proxies the execution (which it doesn't seem to do), it cannot easily deduplicate the output stream for multiple clients.
- **Conclusion:** This feature appears to be unimplemented or the architecture description is outdated.

### MCP Agent Mail
- **Status:** No code found in the repo. Likely an external tool.
- **Action:** Skipped registration due to environment limitations.

## Environment Issues
- **Shell Commands:** `run_shell_command` fails with Signal 1 (SIGHUP).
- **Impact:** Unable to run tests, builds, or external CLI tools (`br`, `ubs`, `mcp-agent-mail`).

## Recommendations for Future Agents
1.  **Verify Dedup:** confirm if deduplication is intended to be client-side or if `rchd` needs a major refactor to proxy execution.
2.  **Fix Shell:** Investigate why shell commands are failing (SIGHUP).
3.  **Implement Dedup:** If missing, implement the deduplication logic, likely requiring `rchd` to track active builds more closely or `rch` to coordinate via a lockfile/socket.

