//! Process-global registry for CLI overrides on self-healing behavior.
//!
//! The override priority for self-healing settings is
//! **CLI > env > config > defaults**. CLI flags (`--no-self-healing`,
//! `--no-hook-auto-start`) are parsed in main() before any subcommand
//! runs, but the config-loading code lives much deeper. Threading a
//! `CliOverrides` parameter through every command handler would be
//! invasive; instead we record CLI overrides in this small atomic
//! registry, then [`apply_to`] is invoked from the config layer to
//! merge them on top of an already-loaded `SelfHealingConfig`.
//!
//! All fields are `AtomicBool`, set once at startup, read freely.
//!
//! ## Wiring (do not break this chain — agents debugging silent flag
//! drops are very unhappy):
//!   1. main.rs parses `cli.no_self_healing` / `cli.no_hook_auto_start`
//!      and calls [`set_no_self_healing`] / [`set_no_hook_auto_start`].
//!   2. main.rs reads [`active_cli_overrides`] and emits one INFO
//!      tracing event so the agent can verify the flag took effect.
//!   3. config.rs::load_config() and load_config_with_sources() both
//!      call [`apply_to`] after env-var overrides, so the loaded
//!      config reflects the CLI flag for every command handler.
//!
//! Added by br-4zf3p (completion debt for bd-18e8).

use rch_common::SelfHealingConfig;
use std::sync::atomic::{AtomicBool, Ordering};

static NO_SELF_HEALING: AtomicBool = AtomicBool::new(false);
static NO_HOOK_AUTO_START: AtomicBool = AtomicBool::new(false);

/// Record `--no-self-healing` from CLI parsing. Once set, never unset
/// (the override only narrows scope).
pub fn set_no_self_healing(value: bool) {
    NO_SELF_HEALING.store(value, Ordering::Release);
}

/// Record `--no-hook-auto-start` from CLI parsing.
pub fn set_no_hook_auto_start(value: bool) {
    NO_HOOK_AUTO_START.store(value, Ordering::Release);
}

/// Read the current `--no-self-healing` override flag.
pub fn no_self_healing() -> bool {
    NO_SELF_HEALING.load(Ordering::Acquire)
}

/// Read the current `--no-hook-auto-start` override flag.
pub fn no_hook_auto_start() -> bool {
    NO_HOOK_AUTO_START.load(Ordering::Acquire)
}

/// Apply CLI overrides to a freshly-loaded SelfHealingConfig. The CLI
/// layer is the highest priority, so it wins over any env-var or config
/// file value.
pub fn apply_to(config: &mut SelfHealingConfig) {
    if no_self_healing() {
        config.hook_starts_daemon = false;
        config.daemon_installs_hooks = false;
    }
    if no_hook_auto_start() {
        config.hook_starts_daemon = false;
    }
}

/// List of currently-active CLI override flag names (for diagnostics
/// like `rch doctor` and structured logging).
pub fn active_cli_overrides() -> Vec<&'static str> {
    let mut out = Vec::new();
    if no_self_healing() {
        out.push("--no-self-healing");
    }
    if no_hook_auto_start() {
        out.push("--no-hook-auto-start");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::SelfHealingConfig;

    /// Reset all atomics. Must be called at the start of any test that
    /// mutates the registry, since AtomicBools are process-global.
    fn reset() {
        NO_SELF_HEALING.store(false, Ordering::Release);
        NO_HOOK_AUTO_START.store(false, Ordering::Release);
    }

    #[test]
    fn test_apply_to_no_self_healing_disables_both() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // TEST START
        reset();
        set_no_self_healing(true);
        let mut config = SelfHealingConfig::default();
        assert!(config.hook_starts_daemon);
        assert!(config.daemon_installs_hooks);
        apply_to(&mut config);
        assert!(!config.hook_starts_daemon);
        assert!(!config.daemon_installs_hooks);
        // TEST PASS
        reset();
    }

    #[test]
    fn test_apply_to_no_hook_auto_start_only_disables_hook_starter() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        set_no_hook_auto_start(true);
        let mut config = SelfHealingConfig::default();
        apply_to(&mut config);
        assert!(!config.hook_starts_daemon);
        assert!(
            config.daemon_installs_hooks,
            "daemon-side healing should remain enabled"
        );
        reset();
    }

    // NB: tests that read the global state must not run concurrently with
    // tests that mutate it. We use a single Mutex to serialize them.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_active_cli_overrides_lists_set_flags() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(active_cli_overrides().is_empty());
        set_no_self_healing(true);
        let active = active_cli_overrides();
        assert!(active.contains(&"--no-self-healing"));
        reset();
    }

    #[test]
    fn test_active_cli_overrides_combined() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        set_no_self_healing(true);
        set_no_hook_auto_start(true);
        let active = active_cli_overrides();
        assert_eq!(active.len(), 2);
        reset();
    }

    #[test]
    fn test_default_state_is_false() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(!no_self_healing());
        assert!(!no_hook_auto_start());
    }
}
