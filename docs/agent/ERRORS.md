# RCH Error Registry (Agent-Facing)

This document is a **machine-friendly** mapping of RCH error codes → **meaning** and a single **suggested_action** (the first recommended remediation step).

For full remediation details and the JSON error envelope, see `docs/api/error-codes.md`.

## Usage (agents)

- Primary key: `error.code` (example: `RCH-E104`)
- Prefer using the structured remediation list when present (`ApiError.remediation`).
- If you need a single next step, use `suggested_action` below.

## Error Code Ranges (Authoritative)

| Range     | Category         | Source Type in Code       |
|-----------|------------------|---------------------------|
| E001-E012 | Config           | `ConfigError`             |
| E013-E018 | Config/PathDeps  | `PathDepError`            |
| E019-E024 | Config/Closure   | `ClosureError`            |
| E100-E113 | SSH              | `SshError`                |
| E200-E209 | Worker           | `WorkerError`             |
| E210-E217 | Worker/Storage   | `StorageError`            |
| E300-E309 | Build            | `BuildCompilationFailed`  |
| E310-E317 | Build/Triage     | `ProcessTriageError`      |
| E400-E409 | Transfer         | `TransferError`           |
| E500-E509 | Internal         | `InternalDaemonSocket`    |

> **Note:** For authoritative definitions, see `rch-common/src/errors/catalog.rs` and `rch/src/error.rs`.

## Registry

| code | category | variant | meaning | suggested_action |
|---|---|---|---|---|
| `RCH-E001` | `config` | `ConfigNotFound` | Configuration file not found | Run `rch init` to create a default configuration |
| `RCH-E002` | `config` | `ConfigReadError` | Failed to read configuration file | Check file permissions on the configuration file |
| `RCH-E003` | `config` | `ConfigParseError` | Configuration file contains invalid TOML syntax | Run `rch config validate` to identify syntax errors |
| `RCH-E004` | `config` | `ConfigValidationError` | Configuration contains invalid values | Run `rch config validate` for detailed diagnostics |
| `RCH-E005` | `config` | `ConfigEnvError` | Environment variable has invalid value | Check the environment variable value format |
| `RCH-E006` | `config` | `ConfigProfileNotFound` | Profile not found in configuration | List available profiles with `rch config profiles` |
| `RCH-E007` | `config` | `ConfigNoWorkers` | No workers are configured | Add at least one worker to your configuration |
| `RCH-E008` | `config` | `ConfigInvalidWorker` | Worker configuration is invalid | Verify worker hostname is correct |
| `RCH-E009` | `config` | `ConfigSshKeyError` | SSH key path is invalid or inaccessible | Check that the SSH key file exists |
| `RCH-E010` | `config` | `ConfigSocketPathError` | Socket path is invalid or inaccessible | Check directory permissions for socket path |
| `RCH-E013` | `config` | `PathDepManifestParseFailed` | Cargo manifest parse failure during path-dependency resolution | Check Cargo.toml syntax with `cargo verify-project` |
| `RCH-E014` | `config` | `PathDepMissing` | Path dependency declared but target directory not found | Verify the path in Cargo.toml `[dependencies]` exists on disk |
| `RCH-E015` | `config` | `PathDepCyclic` | Cyclic path dependency detected in dependency graph | Break the cycle by restructuring crate boundaries |
| `RCH-E016` | `config` | `PathDepPolicyViolation` | Path dependency violates canonical-root topology policy | Ensure all path dependencies are under `/data/projects` |
| `RCH-E017` | `config` | `PathDepMetadataFailed` | cargo metadata invocation failed | Try running `cargo metadata --format-version=1` manually |
| `RCH-E018` | `config` | `PathDepMetadataParseFailed` | cargo metadata output could not be parsed | Check cargo version compatibility |
| `RCH-E019` | `config` | `ClosurePlanFailed` | Dependency closure plan computation failed | Check path dependency graph health with `cargo metadata` |
| `RCH-E020` | `config` | `ClosureFailOpen` | Dependency closure entered fail-open state | Transfer proceeds with project root only (fail-open) |
| `RCH-E021` | `config` | `ClosureHighRisk` | High-risk path dependencies in closure plan | Review flagged dependencies in the plan |
| `RCH-E022` | `config` | `ClosureMissingData` | Required dependency closure data missing | Ensure Cargo.toml and Cargo.lock are present |
| `RCH-E023` | `config` | `ClosureNonDeterministic` | Closure sync ordering is non-deterministic | Report as bug — closure ordering must be deterministic |
| `RCH-E024` | `config` | `ClosureFingerprintMismatch` | Closure manifest fingerprint mismatch | Recompute the closure plan |
| `RCH-E100` | `network` | `SshConnectionFailed` | SSH connection to worker failed | Verify the worker host is reachable: `ping <host>` |
| `RCH-E101` | `network` | `SshAuthFailed` | SSH authentication failed | Verify SSH key is in `authorized_keys` on the worker |
| `RCH-E102` | `network` | `SshKeyError` | SSH key not found or has invalid format | Check that the SSH key file exists at the configured path |
| `RCH-E103` | `network` | `SshHostKeyError` | SSH host key verification failed | Accept the host key: `ssh <user>@<host>` (confirm fingerprint) |
| `RCH-E104` | `network` | `SshTimeout` | SSH command execution timed out | Check network connectivity to the worker |
| `RCH-E105` | `network` | `SshSessionDropped` | SSH session terminated unexpectedly | Check network stability |
| `RCH-E106` | `network` | `NetworkDnsError` | DNS resolution failed for worker host | Verify worker hostname is correct |
| `RCH-E107` | `network` | `NetworkUnreachable` | Network is unreachable | Check network connection on local machine |
| `RCH-E108` | `network` | `NetworkConnectionRefused` | Connection refused by remote host | Verify SSH service is running on worker |
| `RCH-E109` | `network` | `NetworkTimeout` | TCP connection timed out | Check network latency to worker |
| `RCH-E200` | `worker` | `WorkerNoneAvailable` | No workers available for selection | Configure at least one worker in `config.toml` |
| `RCH-E201` | `worker` | `WorkerAllUnhealthy` | All configured workers are unhealthy | Run `rch doctor` to diagnose worker issues |
| `RCH-E202` | `worker` | `WorkerHealthCheckFailed` | Worker failed health check | Verify SSH connectivity to worker |
| `RCH-E203` | `worker` | `WorkerSelfTestFailed` | Worker self-test failed | Run `rch self-test --worker <name>` for details |
| `RCH-E204` | `worker` | `WorkerAtCapacity` | Worker is at maximum capacity | Wait for current builds to complete |
| `RCH-E205` | `worker` | `WorkerMissingToolchain` | Worker is missing required toolchain | Install required toolchain on worker |
| `RCH-E206` | `worker` | `WorkerStateError` | Worker state is inconsistent | Restart the RCH daemon: `rchd restart` |
| `RCH-E207` | `worker` | `WorkerCircuitOpen` | Worker circuit breaker is open | Wait for circuit breaker reset period |
| `RCH-E208` | `worker` | `WorkerSelectionFailed` | Worker selection strategy failed | Verify at least one worker is healthy |
| `RCH-E209` | `worker` | `WorkerLoadQueryFailed` | Failed to query worker load | Verify SSH connectivity to worker |
| `RCH-E210` | `worker` | `WorkerDiskPressureCritical` | Worker disk usage is critically high | Clean up old builds: `rch cache clean --worker <id>` |
| `RCH-E211` | `worker` | `WorkerDiskPressureWarning` | Worker disk usage exceeded warning threshold | Monitor disk usage trend |
| `RCH-E212` | `worker` | `WorkerTelemetryGap` | Worker disk telemetry stale or missing | Check worker health: `rch workers probe <id>` |
| `RCH-E213` | `worker` | `WorkerDiskIoHigh` | Worker disk I/O utilization too high | Wait for I/O-heavy operations to complete |
| `RCH-E214` | `worker` | `WorkerMemoryPressureHigh` | Worker memory pressure exceeds threshold | Review worker slot count |
| `RCH-E215` | `worker` | `WorkerReclaimFailed` | Disk reclaim operation failed | Check worker filesystem health |
| `RCH-E216` | `worker` | `WorkerDiskHeadroomInsufficient` | Insufficient disk headroom for build | Try a different worker with more headroom |
| `RCH-E217` | `worker` | `WorkerReclaimProtected` | Active build protection prevented reclaim | Wait for builds to complete |
| `RCH-E300` | `build` | `BuildCompilationFailed` | Remote compilation failed | Review compilation errors in output |
| `RCH-E301` | `build` | `BuildUnknownCommand` | Build command not recognized | Check that the command is supported |
| `RCH-E302` | `build` | `BuildKilledBySignal` | Build process was killed by signal | Check worker system logs for OOM killer |
| `RCH-E303` | `build` | `BuildTimeout` | Build operation timed out | Increase build timeout in configuration |
| `RCH-E304` | `build` | `BuildOutputError` | Failed to capture build output | Check worker disk space |
| `RCH-E305` | `build` | `BuildWorkdirError` | Remote working directory error | Verify `remote_base_dir` is writable |
| `RCH-E306` | `build` | `BuildToolchainError` | Toolchain wrapper failed | Verify toolchain is installed on worker |
| `RCH-E307` | `build` | `BuildEnvError` | Build environment setup failed | Check environment variable configuration |
| `RCH-E308` | `build` | `BuildIncrementalError` | Incremental build state is corrupted | Run `cargo clean` on remote workspace |
| `RCH-E309` | `build` | `BuildArtifactMissing` | Build artifact not found | Verify build completed successfully |
| `RCH-E310` | `build` | `ProcessTriageAdapterUnavailable` | Process triage adapter unavailable | Ensure process triage adapter binary is installed |
| `RCH-E311` | `build` | `ProcessTriageDetectorUncertain` | Process detector could not classify with confidence | Review process list manually |
| `RCH-E312` | `build` | `ProcessTriagePolicyViolation` | Process triage action violates safe-action policy | Use lower-risk action class or request approval |
| `RCH-E313` | `build` | `ProcessTriageTransportError` | Transport error with process triage adapter | Verify adapter process is running |
| `RCH-E314` | `build` | `ProcessTriageExecutorError` | Process triage executor runtime error | Check adapter logs |
| `RCH-E315` | `build` | `ProcessTriageTimeout` | Process triage operation timed out | Increase timeout in ProcessTriageTimeoutPolicy |
| `RCH-E316` | `build` | `ProcessTriagePartialResult` | Process triage returned partial results | Retry failed actions individually |
| `RCH-E317` | `build` | `ProcessTriageInvalidRequest` | Invalid process triage request | Validate request against contract schema |
| `RCH-E400` | `transfer` | `TransferRsyncFailed` | Rsync transfer failed | Verify rsync is installed on both ends |
| `RCH-E401` | `transfer` | `TransferTimeout` | File sync operation timed out | Increase transfer timeout in configuration |
| `RCH-E402` | `transfer` | `TransferSourceMissing` | Source files not found | Verify source files exist locally |
| `RCH-E403` | `transfer` | `TransferDestError` | Destination path error | Check remote directory permissions |
| `RCH-E404` | `transfer` | `TransferDiskFull` | Insufficient disk space on worker | Clean up old builds on worker |
| `RCH-E405` | `transfer` | `TransferPermissionDenied` | Permission denied during file transfer | Check file ownership on worker |
| `RCH-E406` | `transfer` | `TransferChecksumError` | Transfer checksum mismatch | Retry the transfer |
| `RCH-E407` | `transfer` | `TransferBinaryFailed` | Binary download failed | Check network connectivity |
| `RCH-E408` | `transfer` | `TransferIncomplete` | Transfer completed partially | Retry the transfer operation |
| `RCH-E409` | `transfer` | `TransferProtocolError` | Transfer protocol error | Verify rsync version compatibility |
| `RCH-E500` | `internal` | `InternalDaemonSocket` | Failed to connect to daemon socket | Start the daemon: `rchd start` |
| `RCH-E501` | `internal` | `InternalDaemonProtocol` | Daemon protocol error | Restart the daemon: `rchd restart` |
| `RCH-E502` | `internal` | `InternalDaemonNotRunning` | RCH daemon is not running | Start the daemon: `rchd start` |
| `RCH-E503` | `internal` | `InternalIpcError` | Inter-process communication error | Restart the daemon |
| `RCH-E504` | `internal` | `InternalStateError` | Unexpected internal state | Restart the daemon |
| `RCH-E505` | `internal` | `InternalSerdeError` | Serialization/deserialization error | Check for corrupted state files |
| `RCH-E506` | `internal` | `InternalHookError` | Hook execution failed | Verify hook script exists and is executable |
| `RCH-E507` | `internal` | `InternalMetricsError` | Metrics collection error | Check metrics file permissions |
| `RCH-E508` | `internal` | `InternalLoggingError` | Logging system error | Check log directory permissions |
| `RCH-E509` | `internal` | `InternalUpdateError` | Update check failed | Check network connectivity |

_Total: 88 error codes._
