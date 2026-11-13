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

pub mod injection;
mod log;

pub use log::{
    TerminalInfo, TestGuard, TestLogEntry, TestLogger, TestPhase, TestResult,
    init_global_test_logging,
};

/// Pin worker-side protocol tests to the explicitly selected or sibling build.
///
/// Cargo places test executables under either `deps` or the per-unit
/// `build/<package>/<hash>/out` tree. The worker is uplifted into the profile
/// directory by `cargo build -p rch-wkr` before cross-crate protocol tests;
/// an installed worker or PATH fallback could hide regressions.
#[track_caller]
pub fn worker_binary() -> std::path::PathBuf {
    let binary = std::env::var_os("RCH_WKR_BIN").map_or_else(
        || {
            let executable = std::env::current_exe().expect("locate current test executable");
            let profile = executable
                .ancestors()
                .skip(1)
                .take(5)
                .find(|directory| {
                    matches!(
                        directory.file_name().and_then(|name| name.to_str()),
                        Some("deps" | "build")
                    )
                })
                .and_then(std::path::Path::parent)
                .expect("Cargo profile directory; otherwise set RCH_WKR_BIN");
            profile.join(format!("rch-wkr{}", std::env::consts::EXE_SUFFIX))
        },
        std::path::PathBuf::from,
    );
    assert!(
        binary.is_file(),
        "worker protocol tests require the current rch-wkr build at {}; run `cargo build -p rch-wkr` or set RCH_WKR_BIN to that build",
        binary.display()
    );
    binary.canonicalize().expect("resolve worker test binary")
}
