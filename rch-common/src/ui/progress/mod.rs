//! Progress context for safe, rate-limited terminal updates.
//!
//! This module provides a low-level progress context that focuses on
//! terminal safety: rate limiting, cursor visibility management, and
//! clean teardown on interrupts. It is intentionally simple and ASCII-only
//! to avoid leaving partial escape sequences in mixed-output scenarios.

use crate::ui::OutputContext;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_TERMINAL_WIDTH: u16 = 80;
const MAX_UPDATES_PER_SEC: u32 = 10;
const CLEAR_LINE: &str = "\r\x1b[2K";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

static ACTIVE_CONTEXTS: AtomicUsize = AtomicUsize::new(0);
static RENDER_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct SignalState {
    interrupted: AtomicBool,
    resized: AtomicBool,
}

impl SignalState {
    fn new() -> Self {
        Self {
            interrupted: AtomicBool::new(false),
            resized: AtomicBool::new(false),
        }
    }

    fn mark_interrupted(&self) {
        self.interrupted.store(true, Ordering::SeqCst);
    }

    fn mark_resized(&self) {
        self.resized.store(true, Ordering::SeqCst);
    }

    fn take_resized(&self) -> bool {
        self.resized.swap(false, Ordering::SeqCst)
    }

    #[cfg(test)]
    fn simulate_interrupt(&self) {
        self.mark_interrupted();
    }

    #[cfg(test)]
    fn simulate_resize(&self) {
        self.mark_resized();
    }
}

static SIGNAL_STATE: OnceLock<std::sync::Arc<SignalState>> = OnceLock::new();

fn ensure_signal_state() -> std::sync::Arc<SignalState> {
    SIGNAL_STATE
        .get_or_init(|| {
            let state = std::sync::Arc::new(SignalState::new());
            start_signal_listener(state.clone());
            state
        })
        .clone()
}

fn start_signal_listener(state: std::sync::Arc<SignalState>) {
    #[cfg(unix)]
    {
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let Ok(runtime) = runtime else {
                return;
            };

            runtime.block_on(async move {
                use tokio::signal::unix::{SignalKind, signal};

                let mut sigint = match signal(SignalKind::interrupt()) {
                    Ok(sig) => sig,
                    Err(_) => return,
                };
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(sig) => sig,
                    Err(_) => return,
                };
                let mut sigwinch = match signal(SignalKind::window_change()) {
                    Ok(sig) => sig,
                    Err(_) => return,
                };

                loop {
                    tokio::select! {
                        _ = sigint.recv() => {
                            state.mark_interrupted();
                            cleanup_terminal_if_active();
                        }
                        _ = sigterm.recv() => {
                            state.mark_interrupted();
                            cleanup_terminal_if_active();
                        }
                        _ = sigwinch.recv() => {
                            state.mark_resized();
                        }
                    }
                }
            });
        });
    }
}

fn cleanup_terminal_if_active() {
    if ACTIVE_CONTEXTS.load(Ordering::SeqCst) == 0 {
        return;
    }

    let _lock = RENDER_LOCK.lock();
    let mut buffer = String::new();
    buffer.push_str(CLEAR_LINE);
    buffer.push_str(SHOW_CURSOR);
    let _ = write_stderr(&buffer);
}

fn write_stderr(text: &str) -> std::io::Result<()> {
    let mut stderr = std::io::stderr();
    stderr.write_all(text.as_bytes())?;
    stderr.flush()
}

fn detect_terminal_width_with<F>(get_env: F) -> u16
where
    F: Fn(&str) -> Option<String>,
{
    get_env("COLUMNS")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_TERMINAL_WIDTH)
}

fn detect_terminal_width() -> u16 {
    detect_terminal_width_with(|key| std::env::var(key).ok())
}

#[derive(Debug)]
pub struct RateLimiter {
    start: Instant,
    min_interval_ns: u64,
    last_ns: AtomicU64,
}

impl RateLimiter {
    #[must_use]
    pub fn new(max_per_sec: u32) -> Self {
        let per_sec = max_per_sec.max(1) as u64;
        let min_interval_ns = 1_000_000_000u64 / per_sec;
        Self {
            start: Instant::now(),
            min_interval_ns,
            last_ns: AtomicU64::new(0),
        }
    }

    pub fn allow(&self) -> bool {
        let now_ns = self.now_ns();
        self.allow_with(now_ns)
    }

    pub fn reset(&self) {
        self.last_ns.store(0, Ordering::SeqCst);
    }

    fn now_ns(&self) -> u64 {
        let elapsed = self.start.elapsed();
        let nanos = elapsed.as_nanos();
        nanos.min(u128::from(u64::MAX)) as u64
    }

    fn allow_with(&self, now_ns: u64) -> bool {
        let last = self.last_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(last) < self.min_interval_ns {
            return false;
        }

        self.last_ns
            .compare_exchange(last, now_ns, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    }

    #[cfg(test)]
    fn allow_at(&self, now_ns: u64) -> bool {
        self.allow_with(now_ns)
    }

    #[cfg(test)]
    fn min_interval_ns(&self) -> u64 {
        self.min_interval_ns
    }
}

#[derive(Debug)]
struct TerminalState {
    width: u16,
    cursor_hidden: bool,
}

impl TerminalState {
    fn new() -> Self {
        Self {
            width: detect_terminal_width(),
            cursor_hidden: false,
        }
    }

    fn refresh_width(&mut self) {
        self.width = detect_terminal_width();
    }

    fn truncate(&self, line: &str) -> String {
        let width = self.width.max(1) as usize;
        line.chars().take(width).collect()
    }

    #[cfg(test)]
    fn refresh_width_with<F>(&mut self, get_env: F)
    where
        F: Fn(&str) -> Option<String>,
    {
        self.width = detect_terminal_width_with(get_env);
    }
}

#[derive(Debug)]
struct CleanupGuard {
    enabled: bool,
}

impl CleanupGuard {
    fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn clear_line(&self) {
        if self.enabled {
            let _lock = RENDER_LOCK.lock();
            let _ = write_stderr(CLEAR_LINE);
        }
    }

    fn hide_cursor(&self) {
        if self.enabled {
            let _lock = RENDER_LOCK.lock();
            let _ = write_stderr(HIDE_CURSOR);
        }
    }

    fn show_cursor(&self) {
        if self.enabled {
            let _lock = RENDER_LOCK.lock();
            let _ = write_stderr(SHOW_CURSOR);
        }
    }
}

/// Progress context with safe terminal behavior.
#[derive(Debug)]
pub struct ProgressContext {
    rate_limiter: RateLimiter,
    terminal: TerminalState,
    cleanup_guard: CleanupGuard,
    signal_state: Option<std::sync::Arc<SignalState>>,
    enabled: bool,
}

impl ProgressContext {
    #[must_use]
    pub fn new(ctx: OutputContext) -> Self {
        let stderr_is_tty = std::io::stderr().is_terminal();
        Self::new_with_options(ctx, stderr_is_tty, true)
    }

    fn new_with_options(ctx: OutputContext, stderr_is_tty: bool, listen_signals: bool) -> Self {
        let enabled = stderr_is_tty && matches!(ctx, OutputContext::Interactive);
        let cleanup_guard = CleanupGuard::new(enabled);

        if enabled {
            let previous = ACTIVE_CONTEXTS.fetch_add(1, Ordering::SeqCst);
            if previous == 0 {
                cleanup_guard.hide_cursor();
            }
        }

        let signal_state = if enabled && listen_signals {
            Some(ensure_signal_state())
        } else {
            None
        };

        Self {
            rate_limiter: RateLimiter::new(MAX_UPDATES_PER_SEC),
            terminal: TerminalState::new(),
            cleanup_guard,
            signal_state,
            enabled,
        }
    }

    /// Render a single progress line (rate-limited).
    pub fn render(&mut self, line: &str) {
        if !self.enabled {
            return;
        }

        if !self.rate_limiter.allow() {
            return;
        }

        if let Some(state) = &self.signal_state {
            if state.interrupted.load(Ordering::SeqCst) {
                self.cleanup_guard.clear_line();
                self.cleanup_guard.show_cursor();
                return;
            }

            if state.take_resized() {
                self.terminal.refresh_width();
            }
        }

        let rendered = self.terminal.truncate(line);
        let _lock = RENDER_LOCK.lock();
        let mut buffer = String::new();
        buffer.push_str(CLEAR_LINE);
        buffer.push_str(&rendered);
        let _ = write_stderr(&buffer);
    }

    /// Clear the current progress line.
    pub fn clear(&self) {
        self.cleanup_guard.clear_line();
    }

    #[cfg(test)]
    fn new_for_test(stderr_is_tty: bool) -> Self {
        Self::new_with_options(OutputContext::Interactive, stderr_is_tty, false)
    }
}

impl Drop for ProgressContext {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }

        let previous = ACTIVE_CONTEXTS.fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            self.cleanup_guard.clear_line();
            self.cleanup_guard.show_cursor();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

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
    fn rate_limiter_enforces_interval() {
        let limiter = RateLimiter::new(10);
        let interval = limiter.min_interval_ns();

        assert!(limiter.allow_at(0));
        assert!(!limiter.allow_at(interval / 2));
        assert!(limiter.allow_at(interval));
    }

    #[test]
    fn terminal_width_detects_columns_env() {
        let mut state = TerminalState::new();
        let env = TestEnv::new(&[("COLUMNS", "120")]);
        state.refresh_width_with(|key| env.get(key));
        assert_eq!(state.width, 120);
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
}
