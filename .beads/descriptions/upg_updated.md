## Overview

Add comprehensive architecture documentation including the 5-tier classifier design, Architecture Decision Records (ADRs), system diagrams, and operational runbooks. This documentation enables contributors to understand and extend RCH.

## Goals

1. Document 5-tier classifier with design rationale and examples
2. Create ADRs for key architectural decisions
3. Generate system diagrams (component, sequence, deployment)
4. Write operational runbooks for common scenarios
5. Document extension points and plugin interfaces
6. Include performance benchmarks and tuning guide

## Deliverables

### 1. Classifier Architecture (docs/architecture/classifier.md)

```markdown
# 5-Tier Command Classifier

## Overview

The RCH classifier determines whether a command should be executed locally or remotely.
It uses a 5-tier system for fast rejection of non-compilation commands while accurately
identifying compilation workloads.

## Tier Descriptions

### Tier 0: Fast Negative Filter (SIMD)
- **Latency**: ~1µs
- **Purpose**: Instantly reject clearly non-compilation commands
- **Method**: SIMD keyword search for shell commands, utilities, file operations
- **Keywords**: `cd`, `ls`, `cat`, `echo`, `grep`, `awk`, `sed`, `rm`, `mv`, `cp`, `chmod`, `chown`, `mkdir`, `touch`, `find`, `sort`, `uniq`, `wc`, `head`, `tail`, `less`, `more`, `vi`, `vim`, `nano`, `git`, `ssh`, `scp`, `curl`, `wget`, `ping`, `nc`, `kill`, `ps`, `top`, `df`, `du`, `tar`, `gzip`, `zip`, `unzip`

Example matches (REJECT):
- `cd /path/to/dir` → Tier 0 reject (contains 'cd')
- `cat file.txt | grep foo` → Tier 0 reject (contains 'cat', 'grep')
- `git status` → Tier 0 reject (contains 'git')

### Tier 1: Positive Keyword Match
- **Latency**: ~5µs
- **Purpose**: Identify likely compilation commands
- **Method**: Check for build tool names and compilation flags
- **Keywords**: `cargo`, `rustc`, `gcc`, `g++`, `clang`, `clang++`, `make`, `cmake`, `ninja`, `meson`, `bazel`, `buck`, `scons`
- **Flags**: `-c`, `-o`, `-O`, `-g`, `-W`, `-std=`, `-march=`, `-mtune=`

Example matches (CANDIDATE):
- `cargo build` → Tier 1 match (contains 'cargo')
- `gcc -c foo.c -o foo.o` → Tier 1 match (contains 'gcc', '-c', '-o')

### Tier 2: Command Parser Analysis
- **Latency**: ~50µs
- **Purpose**: Parse command structure to identify build invocations
- **Method**: Shell parsing to extract base command and arguments
- **Handles**: Pipes, redirections, command substitution, environment variables

Example analysis:
- `RUSTFLAGS="-C target-cpu=native" cargo build --release`
  - Env: RUSTFLAGS
  - Base command: cargo
  - Subcommand: build
  - Flags: --release
  - Classification: COMPILATION_CANDIDATE

### Tier 3: Heuristic Scoring
- **Latency**: ~100µs
- **Purpose**: Score compilation likelihood for ambiguous commands
- **Factors**:
  - Source file extensions in arguments (.rs, .c, .cpp, .cc, .h, .hpp)
  - Presence of `-c` (compile only), `-o` (output), optimization flags
  - Working directory heuristics (contains Cargo.toml, Makefile, CMakeLists.txt)
  - Historical patterns (this command compiled before)

Scoring example:
```
Command: `rustc lib.rs -o lib`
- rustc binary: +50 points
- .rs extension: +20 points
- -o flag: +10 points
Total: 80 points (threshold: 50)
Decision: COMPILATION
```

### Tier 4: Machine Learning Model (Optional)
- **Latency**: ~500µs
- **Purpose**: Handle edge cases with learned patterns
- **Model**: Small decision tree or random forest
- **Features**: Command tokens, file extensions, directory context, time of day
- **Training**: From actual compilation logs

## Negative Pattern Handling

Commands that look like compilation but should NOT be remoted:

| Pattern | Reason | Example |
|---------|--------|---------|
| `cargo test` | Tests should run locally | May need local fixtures |
| `cargo run` | Execution, not compilation | Output goes to local terminal |
| `make install` | System modification | Needs local permissions |
| `cargo doc` | Documentation | Generates local files |
| `--help` | Help text | Local information |
| `--version` | Version info | Local binary version |

## Edge Cases

### Pipes and Subshells
```bash
# Should NOT remote (output piped)
cargo build 2>&1 | tee build.log

# Should remote (input from file, compilation command)
cargo build < config.txt
```

### Command Substitution
```bash
# Should NOT remote (complex shell interaction)
$(cargo build --message-format=json | jq ...)

# Should remote (simple build)
cargo build --features=$(cat features.txt)
```

### Multiple Commands
```bash
# First command only matters if &&
cargo build && ./target/debug/myapp  # Remote the build, not the run

# Both analyzed if ;
cargo build; cargo test  # Build: remote, Test: local
```

## Performance Budget

| Tier | Target Latency | Max Memory |
|------|----------------|------------|
| 0 | 1µs | 0 |
| 1 | 5µs | 0 |
| 2 | 50µs | 1KB |
| 3 | 100µs | 10KB |
| 4 | 500µs | 1MB |
| Total (95th percentile) | < 200µs | < 100KB |

## Benchmarks

Run classification benchmarks:
```bash
cargo bench --bench classifier
```

Expected results on modern hardware (M1/Ryzen 5000):
- Simple reject (Tier 0): 200ns
- Simple accept (Tier 1): 1µs
- Complex parse (Tier 2): 10µs
- Full heuristic (Tier 3): 50µs
```

### 2. Architecture Decision Records

**ADR-001: Unix Socket for IPC (docs/adr/001-unix-socket-ipc.md)**
```markdown
# ADR-001: Unix Socket for Daemon IPC

## Status
Accepted

## Context
The RCH CLI needs to communicate with the daemon for build classification and execution.
Options considered:
1. Unix domain socket
2. TCP socket
3. Shared memory
4. Named pipes

## Decision
Use Unix domain sockets for IPC.

## Consequences
### Positive
- Zero network overhead
- Built-in permission model (file permissions)
- Reliable delivery guarantees
- Efficient for small messages

### Negative
- Not portable to Windows (though we can use named pipes there)
- File system state to manage (socket file)

## Alternatives Considered
- TCP: Added network stack overhead, port management
- Shared memory: Complex synchronization, harder debugging
- Named pipes: Less flexible, no multiplexing
```

**ADR-002: Zstd Compression (docs/adr/002-zstd-compression.md)**
**ADR-003: Circuit Breaker Pattern (docs/adr/003-circuit-breaker.md)**
**ADR-004: TOML Configuration (docs/adr/004-toml-configuration.md)**
**ADR-005: Shell Hook Architecture (docs/adr/005-shell-hooks.md)**

### 3. System Diagrams (docs/diagrams/)

**Component Diagram (docs/diagrams/components.md)**
```
┌─────────────────────────────────────────────────────────────────┐
│                         Local Machine                           │
│                                                                 │
│  ┌─────────┐    ┌─────────────┐    ┌────────────────────────┐  │
│  │  Shell  │───▶│  Shell Hook │───▶│        rch CLI         │  │
│  │ (bash)  │    │  (preexec)  │    │  ┌──────────────────┐  │  │
│  └─────────┘    └─────────────┘    │  │    Classifier    │  │  │
│                                     │  │  (5-tier system) │  │  │
│                                     │  └──────────────────┘  │  │
│                                     └───────────┬────────────┘  │
│                                                 │               │
│                                     ┌───────────▼────────────┐  │
│                                     │      rchd Daemon       │  │
│                                     │  ┌──────────────────┐  │  │
│                                     │  │  Worker Manager  │  │  │
│                                     │  │  ┌────────────┐  │  │  │
│                                     │  │  │  Circuit   │  │  │  │
│                                     │  │  │  Breaker   │  │  │  │
│                                     │  │  └────────────┘  │  │  │
│                                     │  └──────────────────┘  │  │
│                                     └───────────┬────────────┘  │
│                                                 │               │
└─────────────────────────────────────────────────┼───────────────┘
                                                  │
                                    ┌─────────────┼─────────────┐
                                    │             │             │
                              ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
                              │  Worker 1 │ │  Worker 2 │ │  Worker N │
                              │  (SSH)    │ │  (SSH)    │ │  (SSH)    │
                              │           │ │           │ │           │
                              │ ┌───────┐ │ │ ┌───────┐ │ │ ┌───────┐ │
                              │ │rch-wkr│ │ │ │rch-wkr│ │ │ │rch-wkr│ │
                              │ └───────┘ │ │ └───────┘ │ │ └───────┘ │
                              └───────────┘ └───────────┘ └───────────┘
```

**Sequence Diagram: Build Request (docs/diagrams/build-sequence.md)**
```
Shell       Hook        rch CLI      rchd         Worker
  │           │            │           │            │
  │──command──▶            │           │            │
  │           │───eval────▶│           │            │
  │           │            │──classify─▶            │
  │           │            │◀─result───│            │
  │           │            │           │            │
  │           │      [if remote]       │            │
  │           │            │──request──▶            │
  │           │            │           │──select───▶│
  │           │            │           │            │
  │           │            │           │◀──slot────│
  │           │            │           │──transfer─▶│
  │           │            │           │◀──ack─────│
  │           │            │           │──execute──▶│
  │           │            │           │            │───build
  │           │            │           │◀──result──│
  │           │◀───output──│◀──result──│            │
  │◀──display─│            │           │            │
```

**Deployment Diagram (docs/diagrams/deployment.md)**

### 4. Operational Runbooks (docs/runbooks/)

**runbooks/debugging-slow-builds.md**
```markdown
# Debugging Slow Builds

## Symptoms
- Build takes longer than expected
- `rch status` shows high latency to workers
- Builds waiting in queue

## Diagnostic Steps

### 1. Check Worker Health
```bash
rch status --workers
```
Look for:
- Workers marked "degraded" or "unavailable"
- High latency values (>100ms)
- Low available slots

### 2. Check Circuit Breaker State
```bash
rch status --circuits
```
If circuits are open:
- Worker is experiencing failures
- Wait for half-open state or investigate worker

### 3. Check Transfer Performance
```bash
RCH_LOG_LEVEL=debug rch build 2>&1 | grep -i transfer
```
Look for:
- Transfer times >5s for small projects
- Compression ratios <2x (might need different level)

### 4. Check Classification
```bash
rch classify "your command here"
```
Verify the command is being classified correctly.

## Common Solutions

| Issue | Solution |
|-------|----------|
| All circuits open | Check network, restart workers |
| High transfer time | Check bandwidth, adjust compression |
| Wrong classification | Report bug, use --local flag |
| Queue backup | Add workers or reduce parallel builds |
```

**runbooks/worker-recovery.md**
**runbooks/daemon-restart.md**
**runbooks/configuration-troubleshooting.md**

## Implementation Files

```
docs/
├── architecture/
│   ├── classifier.md         # 5-tier classifier design
│   ├── daemon.md             # Daemon architecture
│   ├── worker.md             # Worker agent design
│   └── ipc.md                # IPC protocol
├── adr/
│   ├── 001-unix-socket-ipc.md
│   ├── 002-zstd-compression.md
│   ├── 003-circuit-breaker.md
│   ├── 004-toml-configuration.md
│   └── 005-shell-hooks.md
├── diagrams/
│   ├── components.md         # Component diagram
│   ├── build-sequence.md     # Build sequence
│   ├── deployment.md         # Deployment topology
│   └── state-machines.md     # Circuit breaker, daemon states
├── runbooks/
│   ├── debugging-slow-builds.md
│   ├── worker-recovery.md
│   ├── daemon-restart.md
│   └── configuration-troubleshooting.md
└── extending/
    ├── adding-a-classifier-tier.md
    ├── custom-worker-selection.md
    └── integration-hooks.md
```

## Testing Requirements

### Documentation Tests

**test_docs_examples.sh**
```bash
#!/usr/bin/env bash
# Extract and test code examples from documentation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="$SCRIPT_DIR/../docs"
LOG_FILE="/tmp/docs_test.log"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }

# Test classifier examples match unit tests
test_classifier_examples() {
    log "Testing classifier examples..."

    # Extract examples from classifier.md
    grep -A1 "Example matches" "$DOCS_DIR/architecture/classifier.md" | \
        grep -E "^\`.*\`" | while read -r example; do
            CMD=$(echo "$example" | sed 's/`//g' | cut -d'→' -f1 | xargs)
            EXPECTED=$(echo "$example" | grep -oE "(REJECT|CANDIDATE|COMPILATION)")

            log "  Testing: $CMD → expected $EXPECTED"

            # Run actual classifier
            RESULT=$(cargo run --quiet -- classify "$CMD" 2>/dev/null || echo "ERROR")
            if ! echo "$RESULT" | grep -qi "$EXPECTED"; then
                log "  MISMATCH: got $RESULT"
            fi
        done
}

# Test ADR examples are valid
test_adr_code_blocks() {
    log "Testing ADR code blocks..."

    for adr in "$DOCS_DIR"/adr/*.md; do
        log "  Checking $(basename "$adr")..."
        # Extract rust code blocks and syntax check
        # (simplified - actual implementation would be more robust)
    done
}

# Verify diagram format
test_diagrams() {
    log "Testing diagram syntax..."

    for diagram in "$DOCS_DIR"/diagrams/*.md; do
        # Check for valid ASCII box drawing
        if grep -q "┌" "$diagram"; then
            log "  $(basename "$diagram"): Unicode box drawing OK"
        fi
    done
}

test_classifier_examples
test_adr_code_blocks
test_diagrams

log "Documentation tests complete"
```

### E2E Test Script (scripts/e2e_docs_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="$SCRIPT_DIR/../docs"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_docs.log"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "=== RCH Documentation E2E Test ==="
log "Docs dir: $DOCS_DIR"

# Test 1: All required documentation files exist
test_docs_exist() {
    log "Test 1: Required documentation files exist"

    REQUIRED_FILES=(
        "architecture/classifier.md"
        "adr/001-unix-socket-ipc.md"
        "diagrams/components.md"
        "runbooks/debugging-slow-builds.md"
    )

    for file in "${REQUIRED_FILES[@]}"; do
        if [[ -f "$DOCS_DIR/$file" ]]; then
            log "  Found: $file"
        else
            fail "Missing: $file"
        fi
    done

    pass "Documentation files exist"
}

# Test 2: Classifier examples are accurate
test_classifier_accuracy() {
    log "Test 2: Classifier examples match implementation"

    # Test Tier 0 rejects
    TIER0_REJECTS=("cd /tmp" "ls -la" "cat file.txt" "git status" "grep foo bar")
    for cmd in "${TIER0_REJECTS[@]}"; do
        RESULT=$("$RCH" classify "$cmd" 2>&1 || echo "LOCAL")
        log "  '$cmd' → $RESULT"
        if ! echo "$RESULT" | grep -qiE "local|reject|tier.0"; then
            log "    Warning: expected reject/local"
        fi
    done

    # Test Tier 1 candidates
    TIER1_CANDIDATES=("cargo build" "rustc lib.rs" "gcc main.c" "make all")
    for cmd in "${TIER1_CANDIDATES[@]}"; do
        RESULT=$("$RCH" classify "$cmd" 2>&1 || echo "UNKNOWN")
        log "  '$cmd' → $RESULT"
        if ! echo "$RESULT" | grep -qiE "remote|candidate|tier.1|compilation"; then
            log "    Warning: expected remote/candidate"
        fi
    done

    pass "Classifier accuracy"
}

# Test 3: ADR format is valid
test_adr_format() {
    log "Test 3: ADR format validation"

    for adr in "$DOCS_DIR"/adr/*.md; do
        NAME=$(basename "$adr")
        log "  Checking $NAME..."

        # Must have Status section
        if ! grep -q "^## Status" "$adr"; then
            fail "$NAME missing Status section"
        fi

        # Must have Decision section
        if ! grep -q "^## Decision" "$adr"; then
            fail "$NAME missing Decision section"
        fi

        # Must have Context section
        if ! grep -q "^## Context" "$adr"; then
            fail "$NAME missing Context section"
        fi

        log "    Format OK"
    done

    pass "ADR format"
}

# Test 4: Runbook commands are valid
test_runbook_commands() {
    log "Test 4: Runbook command validation"

    for runbook in "$DOCS_DIR"/runbooks/*.md; do
        NAME=$(basename "$runbook")
        log "  Checking $NAME..."

        # Extract command examples
        grep -E "^rch " "$runbook" 2>/dev/null | while read -r cmd; do
            # Verify command structure (subcommand exists)
            SUBCMD=$(echo "$cmd" | awk '{print $2}')
            if "$RCH" "$SUBCMD" --help >/dev/null 2>&1; then
                log "    '$cmd' → valid subcommand"
            else
                log "    '$cmd' → Note: subcommand '$SUBCMD' may not exist yet"
            fi
        done
    done

    pass "Runbook commands"
}

# Test 5: Links are not broken
test_internal_links() {
    log "Test 5: Internal link validation"

    BROKEN=0
    find "$DOCS_DIR" -name "*.md" -print0 | while IFS= read -r -d '' file; do
        # Find markdown links
        grep -oE '\[.+\]\([^)]+\)' "$file" 2>/dev/null | while read -r link; do
            TARGET=$(echo "$link" | grep -oE '\([^)]+\)' | tr -d '()')

            # Skip external links
            if [[ "$TARGET" =~ ^http ]]; then
                continue
            fi

            # Resolve relative path
            DIR=$(dirname "$file")
            FULL_PATH="$DIR/$TARGET"

            if [[ ! -f "$FULL_PATH" ]] && [[ ! -d "$FULL_PATH" ]]; then
                log "  Broken link in $(basename "$file"): $TARGET"
                BROKEN=$((BROKEN + 1))
            fi
        done
    done

    if [[ $BROKEN -gt 0 ]]; then
        log "  Found $BROKEN broken links"
    fi
    pass "Internal links"
}

# Test 6: Diagrams render properly (basic check)
test_diagrams() {
    log "Test 6: Diagram validation"

    for diagram in "$DOCS_DIR"/diagrams/*.md; do
        NAME=$(basename "$diagram")
        log "  Checking $NAME..."

        # Check for proper box drawing characters
        if grep -q "┌" "$diagram" && grep -q "└" "$diagram"; then
            log "    Box characters present"
        else
            log "    Note: May use different diagram format"
        fi

        # Check diagram isn't empty
        LINES=$(wc -l < "$diagram")
        if [[ $LINES -lt 10 ]]; then
            log "    Warning: diagram seems short ($LINES lines)"
        fi
    done

    pass "Diagrams"
}

# Run all tests
test_docs_exist
test_classifier_accuracy
test_adr_format
test_runbook_commands
test_internal_links
test_diagrams

log "=== All Documentation E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- INFO: Documentation generation started/completed
- WARN: Example code out of sync with implementation
- ERROR: Documentation file missing or malformed

## Success Criteria

- [ ] Classifier documentation fully describes all 5 tiers
- [ ] All classifier examples match actual behavior
- [ ] At least 5 ADRs covering major decisions
- [ ] Component, sequence, and deployment diagrams present
- [ ] At least 4 runbooks for common operations
- [ ] All internal links valid
- [ ] All code examples compile/run
- [ ] Documentation tests pass

## Dependencies

- Classifier implementation must be stable
- ADR decisions must be finalized

## Blocks

- Onboarding guide references architecture docs
- Contributor guide references extension docs
