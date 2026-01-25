# Agent-Friendliness Report: Remote Compilation Helper (rch)

**Bead ID**: bd-22w
**Date**: 2026-01-25
**Agent**: Claude Opus 4.5

## Executive Summary

**Status: HIGH AGENT-FRIENDLINESS MATURITY**

rch is already well-optimized for AI coding agent usage:
- TOON output fully integrated (`--format toon`)
- Comprehensive JSON output (`--json`, `RCH_OUTPUT_FORMAT`)
- Structured error responses with suggestions
- Well-documented CLI with examples

## 1. Current State Assessment

### 1.1 Robot Mode Support

| Feature | Status | Details |
|---------|--------|---------|
| `--json` flag | YES | Global flag on all commands |
| `--format` flag | YES | Accepts `json` and `toon` |
| `RCH_OUTPUT_FORMAT` env | YES | Set machine output format |
| `TOON_DEFAULT_FORMAT` env | YES | Default format when --json is set |
| Error as JSON | YES | Errors include structured response |
| Exit codes | YES | Semantic exit codes documented |

### 1.2 Commands with JSON Support

| Command | JSON | TOON | Notes |
|---------|------|------|-------|
| `rch status` | YES | YES | Full system status |
| `rch doctor` | YES | YES | Diagnostics with checks array |
| `rch workers probe` | YES | YES | Connectivity results |
| `rch workers list` | YES | YES | Worker configuration |
| `rch config show` | YES | YES | Configuration values |

### 1.3 Output Envelope Structure

The doctor command output shows excellent structure:
```json
{
  "version": "1",
  "command": "doctor",
  "success": true,
  "data": {
    "checks": [...],
    "summary": {...}
  }
}
```

This follows best practices with:
- Schema version for compatibility
- Command identification
- Success indicator
- Nested data payload

## 2. Documentation Assessment

### 2.1 AGENTS.md

**Status**: EXISTS and comprehensive

Contains:
- Project overview with architecture diagram
- Command classification details (what's intercepted vs passed through)
- Exit code semantics
- Workspace structure
- Code editing discipline rules

### 2.2 README.md

**Status**: EXISTS (28KB)

Contains installation, usage, and configuration documentation.

### 2.3 --help Output

**Status**: EXCELLENT

The `--help` output includes:
- Clear command descriptions
- EXAMPLES section with common workflows
- HOOK MODE explanation
- ENVIRONMENT VARIABLES listing
- CONFIG PRECEDENCE hierarchy

## 3. Scorecard

| Dimension | Score (1-5) | Notes |
|-----------|-------------|-------|
| Documentation | 4 | AGENTS.md present, good --help |
| CLI Ergonomics | 5 | Excellent subcommand structure |
| Robot Mode | 5 | --json, --format, env vars |
| Error Handling | 4 | Structured errors with suggestions |
| Consistency | 4 | Follows suite conventions |
| Zero-shot Usability | 4 | Good --help, examples |
| **Overall** | **4.3** | High maturity |

## 4. Gap Analysis

### 4.1 Minor Gaps Identified

1. **Missing `--help-json`**: Could provide machine-readable help
2. **No `--schema` flag**: Could emit JSON Schema for outputs
3. **No `--capabilities` flag**: Could list all features/commands

### 4.2 Documentation Gaps

1. **Hook Protocol Doc**: stdin/stdout JSON protocol could be more explicit
2. **Worker Selection Algorithm**: Not fully documented for agents
3. **Error Taxonomy**: No formal error code registry

## 5. TOON Integration Status

**Status: FULLY INTEGRATED**

TOON is available via:
- `--format toon` flag
- `RCH_OUTPUT_FORMAT=toon` environment variable
- `TOON_DEFAULT_FORMAT=toon` when `--json` is set

Implementation in `/dp/remote_compilation_helper/rch/src/ui/context.rs`:
```rust
pub enum OutputFormat {
    Json,
    Toon,
}

fn format_machine(&self, value: &serde_json::Value) -> anyhow::Result<String> {
    match self.format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Toon => Ok(toon_rust::encode(value, None)),
    }
}
```

## 6. Recommendations

### 6.1 High Priority (P1)

1. Add `--schema` flag to emit JSON Schema for outputs
2. Create formal error code registry in docs/agent/ERRORS.md

### 6.2 Medium Priority (P2)

1. Add `--help-json` for machine-readable help
2. Document worker selection algorithm formally
3. Add `--capabilities` command for feature discovery

### 6.3 Low Priority (P3)

1. Add example JSONL streaming for long operations
2. Create docs/agent/QUICKSTART.md for agents

## 7. Baseline Artifacts

Captured in `/dp/remote_compilation_helper/agent_baseline/`:
- `help.txt` - Full --help output
- `doctor.json` - Doctor command JSON output
- `status.json` - Status command JSON output (if available)

## 8. Conclusion

rch is already highly agent-friendly with:
- Full TOON integration
- Comprehensive JSON output
- Well-structured error responses
- Good documentation

The remaining work is refinement rather than fundamental integration. Recommend creating focused beads for the P1/P2 recommendations.

---
*Generated by Claude Opus 4.5 during bd-22w execution*
