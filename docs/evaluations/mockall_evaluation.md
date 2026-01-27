# Evaluation: mockall for Type-Safe Mocking in RCH

**Bead:** bd-1yix
**Evaluator:** SilverHawk (claude-code / opus-4.5)
**Date:** 2026-01-27

## Executive Summary

**Recommendation: DO NOT ADOPT mockall at this time.**

While mockall is an excellent library for trait-based mocking, RCH's current manual mock infrastructure is well-suited to its needs. The cost of migration outweighs the benefits, and mockall's constraints don't align well with RCH's mock patterns.

---

## Current RCH Mocking Infrastructure

### Existing Mock Components

| Component | Location | Lines | Purpose |
|-----------|----------|-------|---------|
| `MockSshClient` | `rch-common/src/mock.rs` | ~540 | SSH command execution simulation |
| `MockRsync` | `rch-common/src/mock.rs` | ~150 | File transfer simulation |
| `MockConfig`/`MockRsyncConfig` | `rch-common/src/mock.rs` | ~200 | Behavior configuration |
| `MockWorkerServer` | `rch-common/src/mock_worker.rs` | ~172 | Test lifecycle management |
| `MockTerminal` | `rch/tests/support/mock_terminal.rs` | ~219 | UI testing |
| `MockClock`/`MockFileSystem`/`MockNetwork` | `rch-telemetry/tests/mocks/mod.rs` | ~339 | Benchmark testing |
| Test Factories | `rch/tests/support/factories.rs` | ~340 | Mock data generation |

### Current Approach Strengths

1. **Environment-controlled behavior** - `RCH_MOCK_SSH=1` enables mock mode globally
2. **Invocation recording** - Automatic capture for test verification
3. **Transient failure simulation** - `fail_connect_attempts`, `fail_execute_attempts`
4. **RAII cleanup** - `MockWorkerServer` auto-cleans on drop
5. **Builder pattern** - Flexible mock configuration
6. **CI-friendly** - All mock behavior configurable via environment variables
7. **Full behavioral control** - Command-specific responses via `command_results` HashMap

### Current Approach Limitations

1. Manual boilerplate for each mock type
2. No automatic trait-to-mock generation
3. Must manually update mocks when interfaces change
4. No built-in expectation/verification framework

---

## mockall Capabilities

### Key Features

```rust
// Automatic mock generation from trait
#[automock]
trait SshTransport {
    fn connect(&self) -> Result<()>;
    fn execute(&self, cmd: &str) -> Result<CommandResult>;
}

// In test
let mut mock = MockSshTransport::new();
mock.expect_connect()
    .times(1)
    .returning(|| Ok(()));
mock.expect_execute()
    .with(predicate::eq("cargo build"))
    .returning(|_| Ok(CommandResult { exit_code: 0, ..Default::default() }));
```

### Advantages

- **Type-safe expectations** - Compile-time verification of mock setup
- **Automatic generation** - `#[automock]` generates mock from trait definition
- **Rich matchers** - `predicate::eq()`, `predicate::function()`, custom matchers
- **Call count enforcement** - `times(n)`, `never()`, `at_least(n)`
- **Sequencing** - Enforce call order across multiple mocks
- **Generic support** - Works with generic traits/methods

### Limitations

- **Trait-based** - Requires interfaces defined as traits
- **Static method globals** - Static mock expectations are shared across tests
- **Non-Send complexity** - Requires `_st` variants for non-Send types
- **Macro complexity** - `mock!` syntax for external types is verbose
- **No state simulation** - Less suited for stateful mocks with internal behavior

---

## Comparison Analysis

### Pattern Mismatch

RCH's mocks are **behavioral simulators**, not **expectation verifiers**:

| RCH Pattern | mockall Pattern |
|-------------|-----------------|
| Simulate SSH connection lifecycle | Verify method was called with args |
| Record invocations for later analysis | Assert call count/order upfront |
| Configure failure scenarios via env vars | Configure expectations per-test |
| Global mock state for cross-component tests | Test-local mock instances |
| Simulate transient then success | Assert specific call sequences |

### Code Volume Comparison

**Current approach:**
```rust
// Setup
let mut server = MockWorkerServer::builder()
    .ssh_config(MockConfig::default().with_stdout("output"))
    .rsync_config(MockRsyncConfig::success())
    .build();
server.start();

// Usage - mocks are implicit via RCH_MOCK_SSH
let result = run_remote_build(&worker).await?;

// Verification
let invocations = global_ssh_invocations_snapshot();
assert_eq!(invocations.len(), 3);
```

**With mockall (hypothetical):**
```rust
// Would require refactoring to trait-based design
#[automock]
trait SshClient {
    async fn connect(&mut self) -> Result<()>;
    async fn execute(&self, cmd: &str) -> Result<CommandResult>;
    async fn disconnect(&mut self) -> Result<()>;
}

let mut mock = MockSshClient::new();
mock.expect_connect().times(1).returning(|| Ok(()));
mock.expect_execute()
    .times(1)
    .returning(|_| Ok(CommandResult { exit_code: 0, .. }));
mock.expect_disconnect().times(1).returning(|| Ok(()));

// Would need to inject mock into production code
let result = run_remote_build_with_client(&worker, mock).await?;
```

### Migration Cost

To adopt mockall effectively, RCH would need:

1. **Define traits for all mockable interfaces** - `SshTransport`, `RsyncTransport`, `DaemonClient`, etc.
2. **Refactor production code** - Accept trait objects or generics instead of concrete types
3. **Rewrite all existing mocks** - Convert ~1500 lines of mock code
4. **Update all tests** - Change from invocation-recording to expectation-setting style
5. **Handle async complexity** - RCH is heavily async; mockall async support has caveats

Estimated effort: **40-80 hours** with risk of introducing regressions.

---

## Evaluation Criteria

| Criterion | Current | mockall | Winner |
|-----------|---------|---------|--------|
| Type safety | Medium | High | mockall |
| Boilerplate | High | Low | mockall |
| Behavioral simulation | Excellent | Limited | Current |
| Environment control | Excellent | Poor | Current |
| Transient failures | Built-in | Manual | Current |
| Invocation recording | Built-in | Manual | Current |
| Migration cost | N/A | High | Current |
| Learning curve | Low | Medium | Current |
| CI/E2E testing | Excellent | Complex | Current |

**Score: Current 6, mockall 3**

---

## Recommendations

### Do NOT Adopt mockall Because:

1. **Pattern mismatch** - RCH needs behavioral simulators, not expectation verifiers
2. **Environment-control loss** - `RCH_MOCK_SSH=1` pattern is CI-friendly; mockall requires test-local setup
3. **Existing investment** - ~2000 lines of well-tested mock infrastructure
4. **Migration risk** - Major refactoring required with regression potential
5. **Async complexity** - RCH's async-heavy codebase increases mockall integration difficulty

### Instead, Consider These Improvements:

1. **Extract common mock patterns** into reusable builders
2. **Add assertion helpers** for common invocation verification patterns
3. **Document mock usage** in a testing guide
4. **Consider mockall for NEW components** that have clear trait boundaries

### When mockall WOULD Be Appropriate:

- New isolated components with trait-defined interfaces
- Unit tests requiring precise call-order verification
- Components without the environment-variable control requirement

---

## Conclusion

RCH's hand-rolled mock infrastructure is well-designed for its specific needs: behavioral simulation with environment-variable control, invocation recording, and transient failure simulation. While mockall excels at type-safe expectation-based mocking, adopting it would require substantial architectural changes that don't align with RCH's testing philosophy.

**Verdict: Keep current approach; consider mockall for new isolated components only.**

---

## References

- [mockall on crates.io](https://crates.io/crates/mockall)
- [mockall documentation](https://docs.rs/mockall/latest/mockall/)
- [Rust Mock Shootout](https://asomers.github.io/mock_shootout/)
- [Mocking in Rust: Mockall and alternatives](https://blog.logrocket.com/mocking-rust-mockall-alternatives/)
