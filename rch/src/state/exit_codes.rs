//! Exit codes for RCH CLI commands.
//!
//! These follow sysexits.h conventions where applicable, with RCH-specific
//! codes in the 100-127 range for clear differentiation.

//! Exit codes following sysexits.h conventions where applicable.
//!
//! Standard codes (0-63):
//! - 0: Success
//! - 1: Generic error
//! - 64: Command line usage error (EX_USAGE)
//! - 78: Configuration error (EX_CONFIG)
//!
//! RCH-specific codes (100-127):
//! - 100: Needs setup
//! - 101: Daemon not running
//! - 102: No workers configured
//! - 103: Already at requested version
//! - 104: Lock held by another process
//! - 105: Config needs migration

/// Success - operation completed without errors.
pub const OK: i32 = 0;

/// Generic error - unspecified failure.
pub const ERROR: i32 = 1;

/// Command line usage error (EX_USAGE from sysexits.h).
/// The command was used incorrectly, e.g., wrong number of arguments,
/// invalid flag, invalid argument value.
pub const USAGE: i32 = 64;

/// Configuration error (EX_CONFIG from sysexits.h).
/// Something was found in an unconfigured or misconfigured state.
pub const CONFIG: i32 = 78;

// ============================================================================
// RCH-specific exit codes (100-127)
// ============================================================================

/// RCH needs initial setup.
/// Run: `rch setup` to configure.
pub const NEEDS_SETUP: i32 = 100;

/// RCH daemon is not running.
/// Run: `rchd` or `rch daemon start` to start.
pub const DAEMON_DOWN: i32 = 101;

/// No workers are configured.
/// Run: `rch setup workers` or edit `~/.config/rch/workers.toml`.
pub const NO_WORKERS: i32 = 102;

/// Already at the requested version.
/// This is informational, not an error - the system is in the desired state.
pub const ALREADY_CURRENT: i32 = 103;

/// Operation is locked by another process.
/// Wait for the other operation to complete, or check for stale locks.
pub const LOCKED: i32 = 104;

/// Configuration file needs migration to a newer version.
/// Run: `rch config migrate` to upgrade.
pub const NEEDS_MIGRATION: i32 = 105;

/// Convert an exit code to a human-readable message.
///
/// # Examples
///
/// ```
/// use rch::state::exit_codes;
///
/// assert_eq!(exit_codes::message(0), "Success");
/// assert_eq!(exit_codes::message(100), "RCH needs initial setup (run: rch setup)");
/// ```
pub fn message(code: i32) -> &'static str {
    match code {
        OK => "Success",
        ERROR => "General error",
        USAGE => "Invalid command line usage",
        CONFIG => "Configuration error",
        NEEDS_SETUP => "RCH needs initial setup (run: rch setup)",
        DAEMON_DOWN => "RCH daemon is not running (run: rchd start)",
        NO_WORKERS => "No workers configured (run: rch setup workers)",
        ALREADY_CURRENT => "Already at requested version",
        LOCKED => "Operation locked by another process",
        NEEDS_MIGRATION => "Config needs migration (run: rch config migrate)",
        _ => "Unknown error",
    }
}

/// Check if an exit code indicates success.
pub fn is_success(code: i32) -> bool {
    code == OK
}

/// Check if an exit code indicates the system needs setup.
pub fn is_setup_required(code: i32) -> bool {
    matches!(code, NEEDS_SETUP | NO_WORKERS | NEEDS_MIGRATION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    #[test]
    fn test_exit_code_values() {
        log_test_start("test_exit_code_values");
        // Standard codes
        assert_eq!(OK, 0);
        assert_eq!(ERROR, 1);
        assert_eq!(USAGE, 64);
        assert_eq!(CONFIG, 78);

        // RCH-specific codes have explicit values in 100-127 range
        assert_eq!(NEEDS_SETUP, 100);
        assert_eq!(DAEMON_DOWN, 101);
        assert_eq!(NO_WORKERS, 102);
        assert_eq!(ALREADY_CURRENT, 103);
        assert_eq!(LOCKED, 104);
        assert_eq!(NEEDS_MIGRATION, 105);
    }

    #[test]
    fn test_message() {
        log_test_start("test_message");
        assert_eq!(message(OK), "Success");
        assert!(message(NEEDS_SETUP).contains("setup"));
        assert!(message(DAEMON_DOWN).contains("daemon"));
        assert!(message(NO_WORKERS).contains("workers"));
        assert_eq!(message(999), "Unknown error");
    }

    #[test]
    fn test_is_success() {
        log_test_start("test_is_success");
        assert!(is_success(OK));
        assert!(!is_success(ERROR));
        assert!(!is_success(NEEDS_SETUP));
    }

    #[test]
    fn test_is_setup_required() {
        log_test_start("test_is_setup_required");
        assert!(is_setup_required(NEEDS_SETUP));
        assert!(is_setup_required(NO_WORKERS));
        assert!(is_setup_required(NEEDS_MIGRATION));
        assert!(!is_setup_required(OK));
        assert!(!is_setup_required(ERROR));
        assert!(!is_setup_required(DAEMON_DOWN));
    }
}
