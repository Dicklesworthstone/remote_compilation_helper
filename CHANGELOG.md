# Changelog

This is a synthesized, feature-oriented changelog for the last two months of development.

Scope window: **2025-12-25 through 2026-02-25**.

This document is intentionally organized by **finished capabilities** (not commit-by-commit diffs), and each section groups coherent functionality that is fully landed.

---

## Feature Timeline (Last Two Months)

## 1) Deterministic Multi-Repo Reliability Platform

RCH now includes a complete deterministic reliability stack for multi-repo remote builds, including policy, control loops, remediation, and validation.

### Delivered capability

- Multi-repo topology enforcement for remote execution roots.
- Path-dependency closure planning and preflight validation.
- Repo convergence state tracking and repair workflows.
- Disk-pressure risk scoring + admission/scheduling guards.
- Process triage and bounded remediation escalation.
- Deterministic cancellation orchestration and health signals.
- Unified posture/remediation status surfaces.

### Completed workstreams

- `bd-vvmd` (epic)
- `bd-vvmd.1` Canonical worker filesystem topology
- `bd-vvmd.2` Path-dependency closure + preflight verification
- `bd-vvmd.3` Fleet repo convergence + repair surface
- `bd-vvmd.4` Disk pressure resilience
- `bd-vvmd.5` Process triage and remediation
- `bd-vvmd.6` Error taxonomy, telemetry, operator UX
- `bd-vvmd.7` Comprehensive validation/logging

### Representative commits

- `c1bd5cb`, `7d87d3b`, `a876f0c`, `db0728d`, `c8fe9bf`
- `660e7a4`, `fcfe4e8`, `320780d`, `6bae14b`, `ea3ba1a`
- `b70e4e7`, `a770153`, `3c55240`, `38260cd`, `1b54521`
- `ddd0bec`, `77074ba`, `95c8e80`, `7aefab2`, `1c0257d`

---

## 2) FrankenTUI Migration (Native ftui Stack)

The interactive dashboard/TUI stack has been migrated from `ratatui/crossterm` to the FrankenTUI-native `ftui-*` stack.

### Delivered capability

- Native ftui event/render/layout/widget integration.
- Updated test harness and snapshot rendering behavior.
- TUI behavior parity with prior operations (status/builds/history interactions).

### Completed epic

- `bd-q8g6` Epic: Port TUI from `ratatui+crossterm` to FrankenTUI.

### Representative commits

- `e68db7d`, `365f607`, `86cd921`

---

## 3) Fleet Operations Became Fully Real (No Stubs)

Fleet deploy/status/rollback behavior is now fully operational rather than placeholder logic.

### Delivered capability

- Real preflight checks over SSH.
- Live worker status retrieval.
- Real rollback with artifact/version handling.
- Parallel fleet operations with bounded concurrency.
- Canary and staged deployment controls.

### Completed work

- `bd-rs7w` Epic: Fleet module stub elimination.
- `bd-3029`, `bd-2ch3`, `bd-39j3` feature tracks.

### Representative commits

- `8ce42a3`, `ab7a83c`, `7717457`, `75907e6`
- `92cc5eb`, `1261243`

---

## 4) Hook Execution Pipeline Hardening

The hook path and remote execution pipeline were substantially hardened for correctness, safety, and concurrency stability.

### Delivered capability

- `AllowWithModifiedCommand` transparent interception path.
- Shell-aware command tokenization and robust command rewriting.
- Queue timeout behavior and graceful local fallback on contention.
- Output truncation/SIGPIPE handling and improved daemon communication limits.
- Classification regression/timing-budget coverage.

### Representative commits

- `cfdb411`, `1b867f1`, `412a875`, `8141d20`, `78d2f9f`, `2ff8c3c`

---

## 5) Runtime Coverage Expansion

RCH now supports broader remote-compilation/test command coverage with explicit semantics.

### Delivered capability

- Bun support: `bun test`, `bun typecheck` (with explicit non-intercept list for package/dev commands).
- Cargo test semantics stabilized (including expected exit-code behavior).
- Cargo nextest and cargo bench remote execution support.
- C/C++ pipeline and build-system support expanded/validated.

### Representative commits

- `4bd48c9`, `509ed50`, `343a552`
- `4901ed0`, `75b261e`, `b5e7550`, `dbfa2df`
- `bd-v9pq` closure via true E2E validation

---

## 6) Onboarding and Worker Bootstrap Automation

First-run experience and worker bootstrap are now automated and operator-friendly.

### Delivered capability

- `rch init` guided setup flow.
- Worker discovery from SSH config/aliases.
- Worker provisioning (`workers setup`, `deploy-binary`, `sync-toolchain`).
- Installer easy-mode + service manager integration path.

### Representative commits

- `8dd3b46`, `f40d370`, `9b4c311`, `6903c26`, `99f9bc0`
- `0494a08`, `ec9a7ca`, `0b4c772`, `de88252`

---

## 7) Configuration and Operational Doctoring Suite

Configuration management now supports full lifecycle authoring, diagnostics, and machine-readable introspection.

### Delivered capability

- `config get/set/reset/show/init/validate/lint/doctor/edit/diff/export`.
- Rich precedence and source reporting.
- Operator diagnostics through `rch doctor` and `rch check`.
- Configurable self-healing behavior (hook daemon autostart/hook installation).

### Representative commits

- `a08d565`, `5fff22f`, `41c9719`, `bd36dbd`, `bc077f3`

---

## 8) Queue, Cancellation, and Build Lifecycle Visibility

RCH now has coherent queue/cancel operations and richer lifecycle diagnostics.

### Delivered capability

- Queue visibility with watch/follow modes.
- Build cancellation controls and deterministic cancellation metadata.
- Status integration of cancellation health and stuck-build protections.

### Representative commits

- `da285f0`, `defebdf`, `38260cd`, `1b54521`, `4cc9f7e`

---

## 9) Observability Platform + SpeedScore System

Observability matured from basic status into a full telemetry + scoring stack.

### Delivered capability

- Prometheus metrics and OpenTelemetry tracing integration.
- Worker telemetry ingestion and persistence.
- SpeedScore model with history and CLI/API exposure.
- Benchmark scheduling and trigger orchestration.

### Representative commits

- `60362bb`, `9325707`, `63d1741`, `a0e0f5d`
- `4e2a743`, `381e84f`, `762009c`, `acec405`, `1d4f8ea`

---

## 10) Multi-Surface UX: Rich CLI, Dashboard, and Web

Operator UX now spans structured machine output, rich terminal surfaces, and browser dashboard workflows.

### Delivered capability

- Context-aware output system with machine/hook/plain/rich behavior.
- `dashboard`/`tui` interface with accessibility controls and test/dump modes.
- Web dashboard surface for worker/build/metrics visibility.
- Schema export/list for API consumers.

### Representative commits

- `38a6f80`, `8620e62`, `a14f195`, `123149a`, `b95c8d0`
- `e0ab713` and subsequent web/dashboard tracks
- `365f607` + `86cd921` for current TUI runtime state

---

## 11) Update and Release Integrity System

The update path is now first-class and includes rollback + verification workflows.

### Delivered capability

- Version check/update channels and specific-version installs.
- Backup metadata and rollback support.
- Changelog diffing across multi-version jumps.
- Integrity verification via checksums and signing-oriented release flow.

### Representative commits

- `73ff4d3`, `4868d76`, `c67499a`, `27a7e78`, `6e014ee`, `2caa631`

---

## 12) Security and Safety Hardening

Execution and transport safety posture significantly improved.

### Delivered capability

- Safer SSH defaults and socket handling.
- Shell escaping and command-path safety checks.
- Sensitive value masking improvements.
- External timeout wrappers to prevent runaway/hung remote commands.

### Representative commits

- `a8ed079`, `cb4ba31`, `9df00fa`, `7b71b38`
- `c08af0b`, `3fb98ce`, `fd67cb4`, `2638c6b` (`bd-1nmv` timeout hardening)

---

## 13) Comprehensive Validation and Reliability Test Matrix

Test infrastructure now includes broad true-E2E and reliability-contract coverage.

### Delivered capability

- Expanded true E2E suites across Rust/Bun/C/C++/fleet/hook flows.
- Reliability-focused suites (convergence, triage, fault injection, parity, SLO guardrails, contract drift).
- Property-based and concurrency-focused coverage where relevant.
- Unified reliability suite orchestration and operator runbook support.

### Representative commits

- `0062e96`, `bd0ef1a`, `7f7bf85`, `f6cdbf7`, `966d657`
- `77074ba`, `95c8e80`, `7aefab2`, `1c0257d`, `261a4c7`, `2498cb9`

---

## 14) Platform and Dependency Modernization

Core platform/toolchain and dependency baselines were advanced to support current architecture and runtime behavior.

### Delivered capability

- Workspace moved through stable release cadence into current 1.0.10 baseline.
- Rust/tooling/dependency refreshes aligned with new reliability and TUI architecture.
- Migration from `ratatui/crossterm` to `ftui-*` dependency tree.

### Representative commits

- `29c748a`, `77a779d`, `e68db7d`

---

## Summary

Over this two-month window, RCH evolved from a strong remote compilation core into a full operational platform with:

- deterministic multi-repo reliability controls,
- production-grade fleet and cancellation operations,
- deep observability and telemetry-backed scoring,
- multi-surface operator UX (CLI/TUI/Web), and
- comprehensive validation infrastructure.

The project is now organized around coherent control-plane behavior rather than ad-hoc command plumbing, and the major reliability epics are fully closed.
