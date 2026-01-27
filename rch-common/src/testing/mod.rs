//! Test utilities for RCH.
//!
//! Provides structured test logging, output capture, and debugging infrastructure
//! for consistent test output across the codebase.
//!
//! # Features
//!
//! - JSONL test logs for CI debugging
//! - Structured phase markers (TEST START/PASS/FAIL)
//! - Terminal metadata capture
//! - Zero-boilerplate logging with `TestGuard`
//!
//! # Quick Start (Unit Tests)
//!
//! For simple unit tests, use `TestGuard` which auto-logs pass/fail:
//!
//! ```ignore
//! use rch_common::testing::TestGuard;
//!
//! #[test]
//! fn test_simple() {
//!     let _guard = TestGuard::new("test_simple");
//!     // ... test logic ...
//!     // TEST PASS logged automatically on success
//!     // TEST FAIL logged automatically if test panics
//! }
//! ```
//!
//! Or use the macro for automatic name detection:
//!
//! ```ignore
//! use rch_common::test_guard;
//!
//! #[test]
//! fn test_auto_name() {
//!     let _guard = test_guard!();  // Uses "test_auto_name" as the test name
//!     assert_eq!(1 + 1, 2);
//! }
//! ```
//!
//! # Detailed Logging (E2E/Integration Tests)
//!
//! For tests that need detailed phase logging, use `TestLogger`:
//!
//! ```ignore
//! use rch_common::testing::{TestLogger, TestPhase};
//!
//! #[test]
//! fn test_detailed() {
//!     let logger = TestLogger::for_test("test_detailed");
//!     logger.log(TestPhase::Setup, "Initializing test state");
//!     // ... test logic ...
//!     logger.log(TestPhase::Verify, "Checking results");
//!     logger.pass();  // or logger.fail("reason")
//! }
//! ```
//!
//! # Environment Variables
//!
//! - `RCH_TEST_LOGGING=1`: Force enable structured logging
//! - `RCH_TEST_LOGGING=0`: Force disable (fastest, no I/O)
//! - Default: Enabled in CI (`CI=true`), disabled locally

mod log;

pub use log::{TerminalInfo, TestGuard, TestLogEntry, TestLogger, TestPhase, TestResult};
