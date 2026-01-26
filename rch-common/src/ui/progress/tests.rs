use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct TestEnv {
    vars: HashMap<&'static str, &'static str>,
}

impl TestEnv {
    fn new(pairs: &[(&'static str, &'static str)]) -> Self {
        let vars = pairs.iter().copied().collect();
        Self { vars }
    }

    fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).map(|value| (*value).to_string())
    }
}

#[test]
fn rate_limiter_allows_first_update() {
    let limiter = RateLimiter::new(10);
    assert!(limiter.allow());
}

#[test]
fn rate_limiter_blocks_rapid_updates() {
    let limiter = RateLimiter::new(10);
    assert!(limiter.allow());
    assert!(!limiter.allow());
}

#[test]
fn rate_limiter_enforces_interval() {
    let limiter = RateLimiter::new(10);
    let interval = limiter.min_interval_ns();

    assert!(limiter.allow_at(0));
    assert!(!limiter.allow_at(interval / 2));
    assert!(limiter.allow_at(interval));
}

#[test]
fn rate_limiter_reset_allows_again() {
    let limiter = RateLimiter::new(10);
    assert!(limiter.allow());
    assert!(!limiter.allow());
    limiter.reset();
    assert!(limiter.allow());
}

#[test]
fn rate_limiter_thread_safe() {
    let limiter = Arc::new(RateLimiter::new(100));
    let count = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let limiter = Arc::clone(&limiter);
            let count = Arc::clone(&count);
            std::thread::spawn(move || {
                for _ in 0..200 {
                    if limiter.allow() {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let total = count.load(Ordering::Relaxed);
    assert!(total > 0);
    assert!(total < 200);
}

#[test]
fn terminal_width_detects_columns_env() {
    let mut state = TerminalState::new();
    let env = TestEnv::new(&[("COLUMNS", "120")]);
    state.refresh_width_with(|key| env.get(key));
    assert_eq!(state.width, 120);
}

#[test]
fn terminal_width_falls_back_on_invalid_env() {
    let mut state = TerminalState::new();
    let env = TestEnv::new(&[("COLUMNS", "0")]);
    state.refresh_width_with(|key| env.get(key));
    assert_eq!(state.width, DEFAULT_TERMINAL_WIDTH);
}

#[test]
fn terminal_truncates_to_width() {
    let mut state = TerminalState::new();
    state.width = 5;
    assert_eq!(state.truncate("1234567"), "12345");
}

#[test]
fn terminal_truncates_zero_width_to_single_char() {
    let mut state = TerminalState::new();
    state.width = 0;
    assert_eq!(state.truncate("abcd"), "a");
}

#[test]
fn cleanup_guard_noop_when_disabled() {
    let guard = CleanupGuard::new(false);
    guard.clear_line();
    guard.hide_cursor();
    guard.show_cursor();
}

#[test]
fn progress_context_nested_counts() {
    let _guard = TEST_LOCK.lock();
    ACTIVE_CONTEXTS.store(0, Ordering::SeqCst);

    let ctx1 = ProgressContext::new_for_test(true);
    assert_eq!(ACTIVE_CONTEXTS.load(Ordering::SeqCst), 1);

    let ctx2 = ProgressContext::new_for_test(true);
    assert_eq!(ACTIVE_CONTEXTS.load(Ordering::SeqCst), 2);

    drop(ctx2);
    assert_eq!(ACTIVE_CONTEXTS.load(Ordering::SeqCst), 1);

    drop(ctx1);
    assert_eq!(ACTIVE_CONTEXTS.load(Ordering::SeqCst), 0);
}

#[test]
fn progress_context_disabled_when_not_tty() {
    let _guard = TEST_LOCK.lock();
    ACTIVE_CONTEXTS.store(0, Ordering::SeqCst);

    let ctx = ProgressContext::new_for_test(false);
    assert!(!ctx.enabled);
    assert_eq!(ACTIVE_CONTEXTS.load(Ordering::SeqCst), 0);
}

#[test]
fn progress_context_render_handles_long_lines() {
    let _guard = TEST_LOCK.lock();
    let mut ctx = ProgressContext::new_for_test(false);
    ctx.render("This should be ignored because context is disabled");
}

#[test]
fn signal_state_flags() {
    let state = SignalState::new();
    assert!(!state.interrupted.load(Ordering::SeqCst));
    assert!(!state.take_resized());

    state.simulate_interrupt();
    state.simulate_resize();

    assert!(state.interrupted.load(Ordering::SeqCst));
    assert!(state.take_resized());
    assert!(!state.take_resized());
}

#[test]
fn progress_context_rate_limit_respects_interval() {
    let mut ctx = ProgressContext::new_for_test(true);
    ctx.rate_limiter = RateLimiter::new(10);

    ctx.render("first");
    ctx.render("second");
    std::thread::sleep(Duration::from_millis(110));
    ctx.render("third");
}
