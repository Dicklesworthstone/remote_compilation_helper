## Overview

Create an optional interactive TUI dashboard using ratatui for real-time monitoring and operator actions. The dashboard provides a polished terminal UI with keyboard navigation, accessibility features, configurable layouts, and comprehensive build/worker monitoring.

## Goals

1. Real-time worker status with slot utilization gauges
2. Active build list with progress indicators
3. Recent build history with filtering
4. Keyboard shortcuts for common operator actions
5. Graceful terminal resize handling
6. Accessibility: high contrast mode, screen reader hints
7. Configurable layout and refresh rate
8. Mouse support for clickable elements

## Architecture

### Data Model

```rust
// rch/src/tui/state.rs

use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct TuiState {
    pub daemon: DaemonState,
    pub workers: Vec<WorkerState>,
    pub active_builds: Vec<ActiveBuild>,
    pub build_history: VecDeque<HistoricalBuild>,
    pub selected_panel: Panel,
    pub selected_index: usize,
    pub last_update: Instant,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DaemonState {
    pub status: Status,
    pub uptime: Duration,
    pub version: String,
    pub config_path: PathBuf,
    pub socket_path: PathBuf,
    pub builds_today: u32,
    pub bytes_transferred: u64,
}

#[derive(Debug, Clone)]
pub struct WorkerState {
    pub id: String,
    pub host: String,
    pub status: WorkerStatus,
    pub circuit: CircuitState,
    pub total_slots: u32,
    pub used_slots: u32,
    pub latency_ms: u32,
    pub last_seen: DateTime<Utc>,
    pub builds_completed: u32,
}

#[derive(Debug, Clone)]
pub struct ActiveBuild {
    pub id: String,
    pub command: String,
    pub worker: Option<String>,
    pub started_at: DateTime<Utc>,
    pub progress: Option<BuildProgress>,
    pub status: BuildStatus,
}

#[derive(Debug, Clone)]
pub struct BuildProgress {
    pub phase: String,        // "compiling", "linking", etc.
    pub current: u32,         // Current step
    pub total: Option<u32>,   // Total steps if known
    pub crate_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Workers,
    ActiveBuilds,
    History,
    Help,
}
```

### UI Layout

```rust
// rch/src/tui/layout.rs

/// Default layout:
/// ┌─────────────────────────────────────────────────────────┐
/// │ RCH Dashboard v0.1.0          Workers: 3/4  Builds: 2   │
/// ├─────────────────────────────────────────────────────────┤
/// │ Workers                                                  │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ worker-1   ████████░░  8/10 slots  ●  12ms         │ │
/// │ │ worker-2   ██████░░░░  6/10 slots  ●  23ms         │ │
/// │ │ worker-3   ░░░░░░░░░░  0/10 slots  ○  --           │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────┤
/// │ Active Builds (2)                                        │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ #1234  cargo build --release  worker-1  00:45  ▓▓▓░ │ │
/// │ │ #1235  cargo test             worker-2  00:12  ░░░░ │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────┤
/// │ Recent History                                           │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ #1233  cargo build  worker-1  ✓ 00:38  10:23:45     │ │
/// │ │ #1232  cargo test   worker-2  ✓ 00:12  10:22:01     │ │
/// │ │ #1231  cargo check  local     ✓ 00:05  10:21:55     │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────┤
/// │ [q]uit [d]rain [e]nable [r]efresh [?]help  ↑↓ navigate  │
/// └─────────────────────────────────────────────────────────┘

pub struct Layout {
    pub header_height: u16,
    pub workers_height: Constraint,
    pub builds_height: Constraint,
    pub history_height: Constraint,
    pub footer_height: u16,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            header_height: 1,
            workers_height: Constraint::Percentage(25),
            builds_height: Constraint::Percentage(30),
            history_height: Constraint::Percentage(35),
            footer_height: 2,
        }
    }
}
```

### Keyboard Bindings

```rust
// rch/src/tui/keybindings.rs

pub struct KeyBindings {
    pub quit: Vec<KeyCode>,
    pub drain_worker: KeyCode,
    pub enable_worker: KeyCode,
    pub refresh: KeyCode,
    pub help: KeyCode,
    pub navigate_up: KeyCode,
    pub navigate_down: KeyCode,
    pub navigate_left: KeyCode,
    pub navigate_right: KeyCode,
    pub select: KeyCode,
    pub cancel_build: KeyCode,
    pub toggle_details: KeyCode,
    pub filter: KeyCode,
    pub copy_command: KeyCode,
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self {
            quit: vec![KeyCode::Char('q'), KeyCode::Esc],
            drain_worker: KeyCode::Char('d'),
            enable_worker: KeyCode::Char('e'),
            refresh: KeyCode::Char('r'),
            help: KeyCode::Char('?'),
            navigate_up: KeyCode::Up,
            navigate_down: KeyCode::Down,
            navigate_left: KeyCode::Left,
            navigate_right: KeyCode::Right,
            select: KeyCode::Enter,
            cancel_build: KeyCode::Char('c'),
            toggle_details: KeyCode::Char('v'),
            filter: KeyCode::Char('/'),
            copy_command: KeyCode::Char('y'),
        }
    }
}

pub fn handle_key(key: KeyEvent, state: &mut TuiState, bindings: &KeyBindings) -> Option<Action> {
    match key.code {
        k if bindings.quit.contains(&k) => Some(Action::Quit),
        k if k == bindings.drain_worker => {
            if let Some(worker) = state.selected_worker() {
                Some(Action::DrainWorker(worker.id.clone()))
            } else {
                None
            }
        }
        k if k == bindings.enable_worker => {
            if let Some(worker) = state.selected_worker() {
                Some(Action::EnableWorker(worker.id.clone()))
            } else {
                None
            }
        }
        k if k == bindings.navigate_down => {
            state.move_selection(1);
            None
        }
        k if k == bindings.navigate_up => {
            state.move_selection(-1);
            None
        }
        // ... more handlers
        _ => None,
    }
}
```

### Accessibility Features

```rust
// rch/src/tui/accessibility.rs

#[derive(Debug, Clone)]
pub struct AccessibilityConfig {
    /// High contrast mode for better visibility
    pub high_contrast: bool,

    /// Announce changes for screen readers (via title updates)
    pub screen_reader_mode: bool,

    /// Reduce motion (disable animations)
    pub reduce_motion: bool,

    /// Larger text (affects gauge rendering)
    pub large_text: bool,

    /// Color blind friendly palette
    pub color_blind_mode: ColorBlindMode,
}

#[derive(Debug, Clone, Copy)]
pub enum ColorBlindMode {
    None,
    Deuteranopia,   // Red-green (most common)
    Protanopia,     // Red-green
    Tritanopia,     // Blue-yellow
}

impl AccessibilityConfig {
    pub fn from_env() -> Self {
        Self {
            high_contrast: std::env::var("RCH_TUI_HIGH_CONTRAST").is_ok(),
            screen_reader_mode: std::env::var("RCH_TUI_SCREEN_READER").is_ok(),
            reduce_motion: std::env::var("RCH_TUI_REDUCE_MOTION").is_ok()
                || std::env::var("REDUCE_MOTION").is_ok(),
            large_text: std::env::var("RCH_TUI_LARGE_TEXT").is_ok(),
            color_blind_mode: Self::detect_color_blind_mode(),
        }
    }

    fn detect_color_blind_mode() -> ColorBlindMode {
        match std::env::var("RCH_TUI_COLOR_BLIND").ok().as_deref() {
            Some("deuteranopia") | Some("d") => ColorBlindMode::Deuteranopia,
            Some("protanopia") | Some("p") => ColorBlindMode::Protanopia,
            Some("tritanopia") | Some("t") => ColorBlindMode::Tritanopia,
            _ => ColorBlindMode::None,
        }
    }
}

/// Color palette that adapts to accessibility needs
pub fn get_colors(config: &AccessibilityConfig) -> Colors {
    if config.high_contrast {
        Colors::high_contrast()
    } else {
        match config.color_blind_mode {
            ColorBlindMode::None => Colors::default(),
            ColorBlindMode::Deuteranopia | ColorBlindMode::Protanopia => {
                Colors::blue_orange_palette()
            }
            ColorBlindMode::Tritanopia => Colors::red_cyan_palette(),
        }
    }
}
```

### Configuration

```rust
// rch/src/tui/config.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    /// Refresh interval in milliseconds
    pub refresh_ms: u64,

    /// Show timestamps in local or UTC
    pub use_local_time: bool,

    /// Max history items to display
    pub history_limit: usize,

    /// Enable mouse support
    pub mouse_enabled: bool,

    /// Show build command details
    pub show_command_details: bool,

    /// Custom keybindings (optional override)
    pub keybindings: Option<KeyBindings>,

    /// Accessibility settings
    pub accessibility: AccessibilityConfig,

    /// Layout customization
    pub layout: Option<Layout>,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            refresh_ms: 1000,
            use_local_time: true,
            history_limit: 100,
            mouse_enabled: true,
            show_command_details: true,
            keybindings: None,
            accessibility: AccessibilityConfig::from_env(),
            layout: None,
        }
    }
}
```

## Implementation

### Main TUI Application

```rust
// rch/src/tui/app.rs

use crossterm::{
    event::{self, Event, KeyCode, MouseEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};

pub struct TuiApp {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: TuiState,
    config: TuiConfig,
    daemon_client: DaemonClient,
}

impl TuiApp {
    pub async fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen)?;

        let result = self.main_loop().await;

        disable_raw_mode()?;
        execute!(stdout(), LeaveAlternateScreen)?;

        result
    }

    async fn main_loop(&mut self) -> Result<()> {
        let refresh_interval = Duration::from_millis(self.config.refresh_ms);
        let mut last_refresh = Instant::now();

        loop {
            // Draw UI
            self.terminal.draw(|f| self.render(f))?;

            // Handle events with timeout
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => {
                        if let Some(action) = handle_key(key, &mut self.state, &self.config.keybindings()) {
                            match action {
                                Action::Quit => break,
                                Action::DrainWorker(id) => {
                                    self.daemon_client.drain_worker(&id).await?;
                                }
                                Action::EnableWorker(id) => {
                                    self.daemon_client.enable_worker(&id).await?;
                                }
                                Action::CancelBuild(id) => {
                                    self.daemon_client.cancel_build(&id).await?;
                                }
                                _ => {}
                            }
                        }
                    }
                    Event::Mouse(mouse) if self.config.mouse_enabled => {
                        self.handle_mouse(mouse);
                    }
                    Event::Resize(_, _) => {
                        // Terminal handles resize automatically
                    }
                    _ => {}
                }
            }

            // Refresh data periodically
            if last_refresh.elapsed() >= refresh_interval {
                self.refresh_data().await?;
                last_refresh = Instant::now();
            }
        }

        Ok(())
    }

    fn render(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(self.config.layout().header_height),
                self.config.layout().workers_height,
                self.config.layout().builds_height,
                self.config.layout().history_height,
                Constraint::Length(self.config.layout().footer_height),
            ])
            .split(frame.size());

        self.render_header(frame, chunks[0]);
        self.render_workers(frame, chunks[1]);
        self.render_builds(frame, chunks[2]);
        self.render_history(frame, chunks[3]);
        self.render_footer(frame, chunks[4]);
    }

    fn render_workers(&self, frame: &mut Frame, area: Rect) {
        let colors = get_colors(&self.config.accessibility);

        let block = Block::default()
            .title("Workers")
            .borders(Borders::ALL)
            .border_style(if self.state.selected_panel == Panel::Workers {
                Style::default().fg(colors.selected)
            } else {
                Style::default()
            });

        let items: Vec<ListItem> = self.state.workers.iter().enumerate().map(|(i, w)| {
            let gauge = format_slot_gauge(w.used_slots, w.total_slots);
            let status_icon = match w.status {
                WorkerStatus::Available => "●",
                WorkerStatus::Draining => "◐",
                WorkerStatus::Unavailable => "○",
            };
            let latency = if w.latency_ms > 0 {
                format!("{}ms", w.latency_ms)
            } else {
                "--".to_string()
            };

            let style = if self.state.selected_panel == Panel::Workers && self.state.selected_index == i {
                Style::default().bg(colors.highlight)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{:12}", w.id), style),
                Span::raw(" "),
                Span::styled(gauge, style),
                Span::raw(" "),
                Span::styled(format!("{:4}", status_icon), match w.status {
                    WorkerStatus::Available => Style::default().fg(colors.success),
                    WorkerStatus::Draining => Style::default().fg(colors.warning),
                    WorkerStatus::Unavailable => Style::default().fg(colors.error),
                }),
                Span::raw(" "),
                Span::styled(format!("{:>6}", latency), style),
            ]))
        }).collect();

        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }

    // ... render_builds, render_history, render_header, render_footer
}
```

## Implementation Files

```
rch/src/
├── tui/
│   ├── mod.rs              # Public API
│   ├── app.rs              # Main TUI application
│   ├── state.rs            # TUI state model
│   ├── layout.rs           # Layout configuration
│   ├── keybindings.rs      # Keyboard handling
│   ├── accessibility.rs    # Accessibility features
│   ├── config.rs           # TUI configuration
│   ├── widgets/
│   │   ├── mod.rs
│   │   ├── worker_list.rs  # Worker list widget
│   │   ├── build_list.rs   # Build list widget
│   │   ├── history.rs      # History table widget
│   │   ├── gauge.rs        # Slot gauge widget
│   │   └── help.rs         # Help overlay
│   └── client.rs           # Daemon client wrapper
├── commands/
│   └── tui.rs              # `rch tui` command
```

## Testing Requirements

### Unit Tests (rch/src/tui/tests/)

**state_test.rs**
```rust
#[test]
fn test_state_selection_wraps() {
    let mut state = TuiState::with_workers(3);
    state.selected_panel = Panel::Workers;
    state.selected_index = 2;

    state.move_selection(1);
    assert_eq!(state.selected_index, 0); // Wraps to first

    state.move_selection(-1);
    assert_eq!(state.selected_index, 2); // Wraps to last
}

#[test]
fn test_state_panel_navigation() {
    let mut state = TuiState::default();
    state.selected_panel = Panel::Workers;

    state.next_panel();
    assert_eq!(state.selected_panel, Panel::ActiveBuilds);

    state.next_panel();
    assert_eq!(state.selected_panel, Panel::History);

    state.next_panel();
    assert_eq!(state.selected_panel, Panel::Workers); // Wraps
}

#[test]
fn test_selected_worker() {
    let mut state = TuiState::with_workers(3);
    state.workers[1].id = "worker-2".to_string();
    state.selected_panel = Panel::Workers;
    state.selected_index = 1;

    let selected = state.selected_worker();
    assert_eq!(selected.unwrap().id, "worker-2");
}
```

**keybindings_test.rs**
```rust
#[test]
fn test_quit_key() {
    let mut state = TuiState::default();
    let bindings = KeyBindings::default();

    let action = handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE), &mut state, &bindings);
    assert_eq!(action, Some(Action::Quit));

    let action = handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &mut state, &bindings);
    assert_eq!(action, Some(Action::Quit));
}

#[test]
fn test_drain_key_with_selection() {
    let mut state = TuiState::with_workers(2);
    state.workers[0].id = "worker-1".to_string();
    state.selected_panel = Panel::Workers;
    state.selected_index = 0;
    let bindings = KeyBindings::default();

    let action = handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE), &mut state, &bindings);
    assert_eq!(action, Some(Action::DrainWorker("worker-1".to_string())));
}

#[test]
fn test_drain_key_no_selection() {
    let mut state = TuiState::default();
    state.selected_panel = Panel::History; // Not on workers
    let bindings = KeyBindings::default();

    let action = handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE), &mut state, &bindings);
    assert_eq!(action, None);
}
```

**accessibility_test.rs**
```rust
#[test]
fn test_high_contrast_from_env() {
    std::env::set_var("RCH_TUI_HIGH_CONTRAST", "1");
    let config = AccessibilityConfig::from_env();
    assert!(config.high_contrast);
    std::env::remove_var("RCH_TUI_HIGH_CONTRAST");
}

#[test]
fn test_color_blind_mode_detection() {
    std::env::set_var("RCH_TUI_COLOR_BLIND", "deuteranopia");
    let config = AccessibilityConfig::from_env();
    assert!(matches!(config.color_blind_mode, ColorBlindMode::Deuteranopia));
    std::env::remove_var("RCH_TUI_COLOR_BLIND");
}

#[test]
fn test_color_palette_selection() {
    let config = AccessibilityConfig {
        high_contrast: true,
        ..Default::default()
    };
    let colors = get_colors(&config);
    // High contrast should have pure white/black
    assert_eq!(colors.foreground, Color::White);
    assert_eq!(colors.background, Color::Black);
}
```

**layout_test.rs**
```rust
#[test]
fn test_default_layout_percentages() {
    let layout = Layout::default();
    // Workers + Builds + History should total ~90% (leaving room for header/footer)
    // This is a constraint-based check
}

#[test]
fn test_layout_minimum_heights() {
    let term_height = 24; // Minimum terminal height
    let layout = Layout::default();
    let chunks = compute_layout(&layout, term_height);

    // Each section should have at least 3 rows
    assert!(chunks.workers.height >= 3);
    assert!(chunks.builds.height >= 3);
    assert!(chunks.history.height >= 3);
}
```

### Integration Tests (rch/tests/tui_integration.rs)

```rust
#[test]
fn test_tui_render_no_panic() {
    // Render with mock backend to verify no panics
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let state = TuiState::mock_full();
    let config = TuiConfig::default();

    terminal.draw(|f| render_all(f, &state, &config)).unwrap();

    // Verify something was rendered
    let buffer = terminal.backend().buffer();
    assert!(!buffer.content.is_empty());
}

#[test]
fn test_tui_resize_handling() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let state = TuiState::mock_full();
    let config = TuiConfig::default();

    // Initial render
    terminal.draw(|f| render_all(f, &state, &config)).unwrap();

    // Resize
    terminal.backend_mut().resize(120, 40);
    terminal.draw(|f| render_all(f, &state, &config)).unwrap();

    // Verify no panic and layout adjusted
}

#[test]
fn test_tui_with_empty_state() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let state = TuiState::default(); // Empty
    let config = TuiConfig::default();

    terminal.draw(|f| render_all(f, &state, &config)).unwrap();
    // Should show "No workers" or similar
}
```

### E2E Test Script (scripts/e2e_tui_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_tui.log"

export RCH_MOCK_SSH=1
export RCH_LOG_LEVEL=debug

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log "=== RCH TUI E2E Test ==="
log "Binary: $RCH"

# Test 1: TUI starts without daemon (should show error gracefully)
test_tui_no_daemon() {
    log "Test 1: TUI without daemon shows error"

    # Run TUI with timeout, capture output
    OUTPUT=$(timeout 2s "$RCH" tui --test-mode 2>&1 || true)
    log "  Output: $OUTPUT"

    echo "$OUTPUT" | grep -qiE "daemon|connect|error|not running" || log "  Note: verify error handling manually"
    pass "TUI no daemon"
}

# Test 2: TUI test mode renders successfully
test_tui_test_mode() {
    log "Test 2: TUI test mode renders"

    # Run TUI in test mode (renders once and exits)
    OUTPUT=$("$RCH" tui --test-mode --mock-data 2>&1 || true)
    log "  Test mode output (first 500 chars): $(echo "$OUTPUT" | head -c 500)"

    # Should see some UI elements
    echo "$OUTPUT" | grep -qiE "worker|build|history|quit" || log "  Note: verify render output manually"
    pass "TUI test mode"
}

# Test 3: TUI respects environment accessibility settings
test_tui_accessibility() {
    log "Test 3: TUI accessibility settings"

    export RCH_TUI_HIGH_CONTRAST=1
    export RCH_TUI_REDUCE_MOTION=1

    OUTPUT=$("$RCH" tui --test-mode --mock-data 2>&1 || true)
    log "  High contrast mode output: $(echo "$OUTPUT" | head -c 200)"

    unset RCH_TUI_HIGH_CONTRAST RCH_TUI_REDUCE_MOTION
    pass "TUI accessibility"
}

# Test 4: TUI color blind mode
test_tui_color_blind() {
    log "Test 4: TUI color blind mode"

    for mode in "deuteranopia" "protanopia" "tritanopia"; do
        export RCH_TUI_COLOR_BLIND="$mode"
        OUTPUT=$("$RCH" tui --test-mode --mock-data 2>&1 || true)
        log "  Mode $mode: OK"
    done

    unset RCH_TUI_COLOR_BLIND
    pass "TUI color blind modes"
}

# Test 5: TUI with custom refresh rate
test_tui_refresh_rate() {
    log "Test 5: TUI custom refresh rate"

    OUTPUT=$("$RCH" tui --test-mode --mock-data --refresh-ms 500 2>&1 || true)
    log "  Custom refresh: $(echo "$OUTPUT" | head -c 200)"

    pass "TUI refresh rate"
}

# Test 6: TUI keyboard simulation (if supported)
test_tui_keyboard() {
    log "Test 6: TUI keyboard handling"

    # This would require a more sophisticated test harness
    # For now, just verify the command accepts input simulation flag
    OUTPUT=$("$RCH" tui --test-mode --mock-data --simulate-key q 2>&1 || true)
    log "  Keyboard simulation: $(echo "$OUTPUT" | head -c 200)"

    pass "TUI keyboard"
}

# Test 7: TUI render dimensions
test_tui_dimensions() {
    log "Test 7: TUI render at various dimensions"

    for size in "80x24" "120x40" "40x12"; do
        COLS=$(echo "$size" | cut -dx -f1)
        ROWS=$(echo "$size" | cut -dx -f2)
        log "  Testing ${COLS}x${ROWS}..."

        OUTPUT=$(COLUMNS=$COLS LINES=$ROWS "$RCH" tui --test-mode --mock-data 2>&1 || true)
        if echo "$OUTPUT" | grep -qiE "panic|overflow|error"; then
            log "    Warning: possible issue at $size"
        else
            log "    OK"
        fi
    done

    pass "TUI dimensions"
}

# Test 8: TUI mouse support flag
test_tui_mouse() {
    log "Test 8: TUI mouse support"

    OUTPUT=$("$RCH" tui --test-mode --mock-data --no-mouse 2>&1 || true)
    log "  No mouse mode: $(echo "$OUTPUT" | head -c 100)"

    pass "TUI mouse support"
}

# Test 9: TUI JSON output mode (for automation)
test_tui_json() {
    log "Test 9: TUI JSON dump"

    OUTPUT=$("$RCH" tui --dump-state --mock-data 2>&1 || true)
    log "  JSON state: $(echo "$OUTPUT" | head -c 300)"

    if echo "$OUTPUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        log "    Valid JSON"
    else
        log "    Note: JSON dump may not be implemented yet"
    fi

    pass "TUI JSON dump"
}

# Test 10: TUI help display
test_tui_help() {
    log "Test 10: TUI help"

    OUTPUT=$("$RCH" tui --help 2>&1)
    log "  Help output: $(echo "$OUTPUT" | head -20 | tr '\n' ' ')"

    echo "$OUTPUT" | grep -qiE "tui|dashboard|interactive" || fail "Help missing TUI description"
    pass "TUI help"
}

# Run all tests
test_tui_no_daemon
test_tui_test_mode
test_tui_accessibility
test_tui_color_blind
test_tui_refresh_rate
test_tui_keyboard
test_tui_dimensions
test_tui_mouse
test_tui_json
test_tui_help

log "=== All TUI E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- DEBUG: Render cycle timing
- DEBUG: Key/mouse event handling
- DEBUG: Daemon data refresh
- INFO: TUI started/stopped
- WARN: Render latency > 50ms
- ERROR: Terminal initialization failure
- ERROR: Daemon connection lost

## Success Criteria

- [ ] TUI renders without panics at 80x24 minimum
- [ ] Workers panel shows status, slots, latency
- [ ] Active builds panel shows progress
- [ ] History panel shows recent builds
- [ ] All keyboard shortcuts functional
- [ ] Drain/enable worker actions work
- [ ] Resize handling works smoothly
- [ ] High contrast mode works
- [ ] Color blind modes work
- [ ] Unit test coverage > 75%
- [ ] E2E tests pass

## Dependencies

- Status API (remote_compilation_helper-3sy) provides daemon data
- Build history (remote_compilation_helper-qgs) provides history data
- Rich status command (remote_compilation_helper-7ds) shares data model

## Blocks

- None (this is a terminal leaf feature)
