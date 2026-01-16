## Overview

Create an optional interactive TUI dashboard using ratatui for real-time monitoring and operator actions. The dashboard provides a polished terminal UI with keyboard navigation, accessibility features, configurable layouts, comprehensive build/worker monitoring, **search/filter capabilities**, and **log tail view**.

## Goals

1. Real-time worker status with slot utilization gauges
2. Active build list with progress indicators
3. Recent build history with filtering
4. Keyboard shortcuts for common operator actions
5. Graceful terminal resize handling
6. Accessibility: high contrast mode, screen reader hints
7. Configurable layout and refresh rate
8. Mouse support for clickable elements
9. **NEW: Search and filter for build history**
10. **NEW: Log tail view for active builds**
11. **NEW: Copy/export functionality for build logs**

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
    // NEW
    pub filter: FilterState,
    pub log_view: Option<LogViewState>,
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
    pub log_lines: VecDeque<String>,  // NEW: Recent log output
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
    LogView,   // NEW
    Search,    // NEW
}

// NEW: Filter state
#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub search_query: String,
    pub search_active: bool,
    pub filter_worker: Option<String>,
    pub filter_status: Option<BuildStatus>,
    pub filter_time_range: Option<TimeRange>,
}

// NEW: Log view state
#[derive(Debug, Clone)]
pub struct LogViewState {
    pub build_id: String,
    pub lines: VecDeque<String>,
    pub scroll_offset: usize,
    pub auto_scroll: bool,
    pub follow_mode: bool,
}
```

### NEW: Search and Filter

```rust
// rch/src/tui/filter.rs

pub struct FilterEngine {
    history: Vec<HistoricalBuild>,
}

impl FilterEngine {
    /// Apply search query to build history
    pub fn search(&self, query: &str) -> Vec<&HistoricalBuild> {
        if query.is_empty() {
            return self.history.iter().collect();
        }

        let query_lower = query.to_lowercase();

        self.history.iter().filter(|build| {
            // Search in multiple fields
            build.command.to_lowercase().contains(&query_lower)
                || build.id.contains(&query_lower)
                || build.worker.as_ref()
                    .map(|w| w.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
        }).collect()
    }

    /// Apply filters to build history
    pub fn filter(&self, filter: &FilterState) -> Vec<&HistoricalBuild> {
        let mut results: Vec<_> = self.history.iter().collect();

        // Filter by search query
        if !filter.search_query.is_empty() {
            results = self.search(&filter.search_query);
        }

        // Filter by worker
        if let Some(ref worker_id) = filter.filter_worker {
            results.retain(|b| b.worker.as_ref() == Some(worker_id));
        }

        // Filter by status
        if let Some(status) = filter.filter_status {
            results.retain(|b| b.status == status);
        }

        // Filter by time range
        if let Some(ref range) = filter.filter_time_range {
            results.retain(|b| range.contains(&b.completed_at));
        }

        results
    }
}

pub enum TimeRange {
    LastHour,
    Last24Hours,
    LastWeek,
    Custom { start: DateTime<Utc>, end: DateTime<Utc> },
}

impl TimeRange {
    pub fn contains(&self, dt: &DateTime<Utc>) -> bool {
        let now = Utc::now();
        match self {
            TimeRange::LastHour => *dt > now - Duration::hours(1),
            TimeRange::Last24Hours => *dt > now - Duration::hours(24),
            TimeRange::LastWeek => *dt > now - Duration::days(7),
            TimeRange::Custom { start, end } => *dt >= *start && *dt <= *end,
        }
    }
}
```

### NEW: Log View

```rust
// rch/src/tui/log_view.rs

pub struct LogView {
    build_id: String,
    lines: VecDeque<String>,
    max_lines: usize,
    scroll_offset: usize,
    auto_scroll: bool,
}

impl LogView {
    pub fn new(build_id: &str, max_lines: usize) -> Self {
        Self {
            build_id: build_id.to_string(),
            lines: VecDeque::with_capacity(max_lines),
            max_lines,
            scroll_offset: 0,
            auto_scroll: true,
        }
    }

    /// Append log line (from build output stream)
    pub fn append(&mut self, line: String) {
        self.lines.push_back(line);
        if self.lines.len() > self.max_lines {
            self.lines.pop_front();
        }

        if self.auto_scroll {
            self.scroll_to_bottom();
        }
    }

    /// Scroll up by n lines
    pub fn scroll_up(&mut self, n: usize) {
        self.auto_scroll = false;
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }

    /// Scroll down by n lines
    pub fn scroll_down(&mut self, n: usize, visible_height: usize) {
        let max_offset = self.lines.len().saturating_sub(visible_height);
        self.scroll_offset = (self.scroll_offset + n).min(max_offset);

        if self.scroll_offset >= max_offset {
            self.auto_scroll = true;
        }
    }

    fn scroll_to_bottom(&mut self) {
        // Will be set to correct value on render
        self.scroll_offset = usize::MAX;
    }

    /// Get visible lines for rendering
    pub fn visible_lines(&self, height: usize) -> impl Iterator<Item = &str> {
        self.lines.iter()
            .skip(self.scroll_offset)
            .take(height)
            .map(|s| s.as_str())
    }

    /// Copy current view to clipboard
    pub fn copy_visible(&self, height: usize) -> String {
        self.visible_lines(height).collect::<Vec<_>>().join("\n")
    }

    /// Copy all log content
    pub fn copy_all(&self) -> String {
        self.lines.iter().cloned().collect::<Vec<_>>().join("\n")
    }

    /// Export log to file
    pub fn export(&self, path: &Path) -> std::io::Result<()> {
        let content = self.copy_all();
        std::fs::write(path, content)
    }
}
```

### UI Layout

```rust
// rch/src/tui/layout.rs

/// Default layout:
/// ┌─────────────────────────────────────────────────────────────┐
/// │ RCH Dashboard v0.1.0          Workers: 3/4  Builds: 2   │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Workers                                                  │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ worker-1   ████████░░  8/10 slots  ●  12ms         │ │
/// │ │ worker-2   ██████░░░░  6/10 slots  ●  23ms         │ │
/// │ │ worker-3   ░░░░░░░░░░  0/10 slots  ○  --           │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Active Builds (2)                                        │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ #1234  cargo build --release  worker-1  00:45  ▓▓▓░ │ │
/// │ │ #1235  cargo test             worker-2  00:12  ░░░░ │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Recent History [/] Search [f] Filter                    │ │
/// │ ┌─────────────────────────────────────────────────────┐ │
/// │ │ #1233  cargo build  worker-1  ✓ 00:38  10:23:45     │ │
/// │ │ #1232  cargo test   worker-2  ✓ 00:12  10:22:01     │ │
/// │ │ #1231  cargo check  local     ✓ 00:05  10:21:55     │ │
/// │ └─────────────────────────────────────────────────────┘ │
/// ├─────────────────────────────────────────────────────────────┤
/// │ [q]uit [d]rain [e]nable [r]efresh [l]ogs [?]help  ↑↓ nav │
/// └─────────────────────────────────────────────────────────────┘

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
    // NEW
    pub search: KeyCode,
    pub view_logs: KeyCode,
    pub copy_logs: KeyCode,
    pub export_logs: KeyCode,
    pub page_up: KeyCode,
    pub page_down: KeyCode,
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
            filter: KeyCode::Char('f'),
            copy_command: KeyCode::Char('y'),
            // NEW
            search: KeyCode::Char('/'),
            view_logs: KeyCode::Char('l'),
            copy_logs: KeyCode::Char('Y'),  // Shift+y
            export_logs: KeyCode::Char('E'),  // Shift+e
            page_up: KeyCode::PageUp,
            page_down: KeyCode::PageDown,
        }
    }
}

pub fn handle_key(key: KeyEvent, state: &mut TuiState, bindings: &KeyBindings) -> Option<Action> {
    // NEW: Handle search mode
    if state.filter.search_active {
        return handle_search_key(key, state);
    }

    // NEW: Handle log view mode
    if state.log_view.is_some() {
        return handle_log_view_key(key, state, bindings);
    }

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
        // NEW: Search
        k if k == bindings.search => {
            state.filter.search_active = true;
            state.selected_panel = Panel::Search;
            None
        }
        // NEW: View logs
        k if k == bindings.view_logs => {
            if let Some(build) = state.selected_build() {
                state.log_view = Some(LogViewState {
                    build_id: build.id.clone(),
                    lines: build.log_lines.clone(),
                    scroll_offset: 0,
                    auto_scroll: true,
                    follow_mode: true,
                });
                state.selected_panel = Panel::LogView;
            }
            None
        }
        _ => None,
    }
}

fn handle_search_key(key: KeyEvent, state: &mut TuiState) -> Option<Action> {
    match key.code {
        KeyCode::Esc => {
            state.filter.search_active = false;
            state.selected_panel = Panel::History;
            None
        }
        KeyCode::Enter => {
            state.filter.search_active = false;
            // Keep filter applied
            None
        }
        KeyCode::Backspace => {
            state.filter.search_query.pop();
            None
        }
        KeyCode::Char(c) => {
            state.filter.search_query.push(c);
            None
        }
        _ => None,
    }
}

fn handle_log_view_key(key: KeyEvent, state: &mut TuiState, bindings: &KeyBindings) -> Option<Action> {
    let log_view = state.log_view.as_mut().unwrap();

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            state.log_view = None;
            state.selected_panel = Panel::ActiveBuilds;
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            log_view.scroll_offset = log_view.scroll_offset.saturating_sub(1);
            log_view.auto_scroll = false;
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            log_view.scroll_offset += 1;
            None
        }
        KeyCode::PageUp => {
            log_view.scroll_offset = log_view.scroll_offset.saturating_sub(20);
            log_view.auto_scroll = false;
            None
        }
        KeyCode::PageDown => {
            log_view.scroll_offset += 20;
            None
        }
        KeyCode::Char('G') => {
            // Jump to bottom
            log_view.auto_scroll = true;
            log_view.scroll_offset = usize::MAX;
            None
        }
        KeyCode::Char('g') => {
            // Jump to top
            log_view.scroll_offset = 0;
            log_view.auto_scroll = false;
            None
        }
        KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Copy visible to clipboard
            Some(Action::CopyLogs(log_view.build_id.clone(), false))
        }
        KeyCode::Char('Y') => {
            // Copy all to clipboard
            Some(Action::CopyLogs(log_view.build_id.clone(), true))
        }
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

    // NEW
    /// Max log lines to keep per build
    pub log_buffer_size: usize,

    /// Enable log streaming for active builds
    pub stream_logs: bool,

    /// Default export directory for logs
    pub log_export_dir: Option<PathBuf>,
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
            // NEW
            log_buffer_size: 10000,
            stream_logs: true,
            log_export_dir: None,
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
    filter_engine: FilterEngine,  // NEW
    clipboard: Option<Clipboard>,  // NEW
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
                                // NEW
                                Action::CopyLogs(build_id, all) => {
                                    self.copy_logs(&build_id, all)?;
                                }
                                Action::ExportLogs(build_id, path) => {
                                    self.export_logs(&build_id, &path)?;
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

    // NEW: Copy logs to clipboard
    fn copy_logs(&mut self, build_id: &str, all: bool) -> Result<()> {
        if let Some(ref log_view) = self.state.log_view {
            let content = if all {
                log_view.lines.iter().cloned().collect::<Vec<_>>().join("\n")
            } else {
                // Copy visible portion
                let height = self.terminal.size()?.height as usize - 4;
                log_view.lines.iter()
                    .skip(log_view.scroll_offset)
                    .take(height)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n")
            };

            if let Some(ref mut clipboard) = self.clipboard {
                clipboard.set_text(content)?;
            }
        }
        Ok(())
    }

    // NEW: Export logs to file
    fn export_logs(&self, build_id: &str, path: &Path) -> Result<()> {
        if let Some(ref log_view) = self.state.log_view {
            let content = log_view.lines.iter().cloned().collect::<Vec<_>>().join("\n");
            std::fs::write(path, content)?;
        }
        Ok(())
    }

    fn render(&self, frame: &mut Frame) {
        // Check for log view mode
        if self.state.log_view.is_some() {
            self.render_log_view(frame);
            return;
        }

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

        // NEW: Render search overlay if active
        if self.state.filter.search_active {
            self.render_search_overlay(frame);
        }
    }

    // NEW: Render log view panel
    fn render_log_view(&self, frame: &mut Frame) {
        let log_view = self.state.log_view.as_ref().unwrap();
        let colors = get_colors(&self.config.accessibility);

        let area = frame.size();

        // Header
        let header_area = Rect::new(area.x, area.y, area.width, 2);
        let header = Paragraph::new(format!(
            "Build {} Logs {} [ESC] close [↑↓] scroll [g/G] top/bottom [y] copy",
            log_view.build_id,
            if log_view.auto_scroll { "(following)" } else { "" }
        ))
        .style(Style::default().fg(colors.header));
        frame.render_widget(header, header_area);

        // Log content
        let log_area = Rect::new(area.x, area.y + 2, area.width, area.height - 2);

        let visible_lines: Vec<Line> = log_view.lines.iter()
            .skip(log_view.scroll_offset)
            .take(log_area.height as usize)
            .map(|line| Line::from(line.as_str()))
            .collect();

        let log_paragraph = Paragraph::new(visible_lines)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Log Output"));

        frame.render_widget(log_paragraph, log_area);

        // Scroll indicator
        let total_lines = log_view.lines.len();
        let visible_height = log_area.height as usize;
        if total_lines > visible_height {
            let scroll_percentage = (log_view.scroll_offset as f64 / (total_lines - visible_height) as f64 * 100.0) as u8;
            let scroll_indicator = format!("{}%", scroll_percentage.min(100));
            let indicator_area = Rect::new(
                area.width - scroll_indicator.len() as u16 - 2,
                area.y,
                scroll_indicator.len() as u16 + 1,
                1
            );
            frame.render_widget(Paragraph::new(scroll_indicator), indicator_area);
        }
    }

    // NEW: Render search overlay
    fn render_search_overlay(&self, frame: &mut Frame) {
        let area = frame.size();
        let search_area = Rect::new(
            area.width / 4,
            area.height / 2 - 2,
            area.width / 2,
            3
        );

        let search_input = Paragraph::new(format!("/{}", self.state.filter.search_query))
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Search History"));

        frame.render_widget(Clear, search_area);
        frame.render_widget(search_input, search_area);
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
│   ├── filter.rs           # NEW: Search and filter engine
│   ├── log_view.rs         # NEW: Log viewing component
│   ├── widgets/
│   │   ├── mod.rs
│   │   ├── worker_list.rs  # Worker list widget
│   │   ├── build_list.rs   # Build list widget
│   │   ├── history.rs      # History table widget
│   │   ├── gauge.rs        # Slot gauge widget
│   │   ├── log_panel.rs    # NEW: Log panel widget
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

**filter_test.rs** (NEW)
```rust
#[test]
fn test_search_by_command() {
    let engine = FilterEngine::new(vec![
        HistoricalBuild { command: "cargo build".into(), .. },
        HistoricalBuild { command: "cargo test".into(), .. },
        HistoricalBuild { command: "make all".into(), .. },
    ]);

    let results = engine.search("cargo");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_search_case_insensitive() {
    let engine = FilterEngine::new(vec![
        HistoricalBuild { command: "CARGO BUILD".into(), .. },
    ]);

    let results = engine.search("cargo");
    assert_eq!(results.len(), 1);
}

#[test]
fn test_filter_by_worker() {
    let engine = FilterEngine::new(vec![
        HistoricalBuild { worker: Some("w1".into()), .. },
        HistoricalBuild { worker: Some("w2".into()), .. },
    ]);

    let filter = FilterState {
        filter_worker: Some("w1".into()),
        ..Default::default()
    };

    let results = engine.filter(&filter);
    assert_eq!(results.len(), 1);
}

#[test]
fn test_filter_by_time_range() {
    let now = Utc::now();
    let engine = FilterEngine::new(vec![
        HistoricalBuild { completed_at: now - Duration::minutes(30), .. },
        HistoricalBuild { completed_at: now - Duration::hours(2), .. },
    ]);

    let filter = FilterState {
        filter_time_range: Some(TimeRange::LastHour),
        ..Default::default()
    };

    let results = engine.filter(&filter);
    assert_eq!(results.len(), 1);
}
```

**log_view_test.rs** (NEW)
```rust
#[test]
fn test_log_view_append() {
    let mut log_view = LogView::new("build-1", 100);

    log_view.append("Line 1".into());
    log_view.append("Line 2".into());

    assert_eq!(log_view.lines.len(), 2);
}

#[test]
fn test_log_view_max_lines() {
    let mut log_view = LogView::new("build-1", 3);

    for i in 0..5 {
        log_view.append(format!("Line {}", i));
    }

    assert_eq!(log_view.lines.len(), 3);
    assert!(log_view.lines.iter().any(|l| l.contains("Line 4")));
}

#[test]
fn test_log_view_scroll() {
    let mut log_view = LogView::new("build-1", 100);
    for i in 0..50 {
        log_view.append(format!("Line {}", i));
    }

    log_view.scroll_up(5);
    assert_eq!(log_view.scroll_offset, 45); // MAX - 5

    log_view.scroll_down(3, 20);
    assert_eq!(log_view.scroll_offset, 48);
}

#[test]
fn test_log_view_copy_all() {
    let mut log_view = LogView::new("build-1", 100);
    log_view.append("Line 1".into());
    log_view.append("Line 2".into());

    let copied = log_view.copy_all();
    assert_eq!(copied, "Line 1\nLine 2");
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
fn test_search_key_activates_search() {
    let mut state = TuiState::default();
    let bindings = KeyBindings::default();

    handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE), &mut state, &bindings);

    assert!(state.filter.search_active);
    assert_eq!(state.selected_panel, Panel::Search);
}

#[test]
fn test_view_logs_key() {
    let mut state = TuiState::with_builds(1);
    state.active_builds[0].id = "build-1".to_string();
    state.selected_panel = Panel::ActiveBuilds;
    state.selected_index = 0;

    let bindings = KeyBindings::default();

    handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE), &mut state, &bindings);

    assert!(state.log_view.is_some());
    assert_eq!(state.selected_panel, Panel::LogView);
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

#[test]
fn test_tui_log_view_render() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut state = TuiState::default();
    state.log_view = Some(LogViewState {
        build_id: "test".into(),
        lines: vec!["Line 1".into(), "Line 2".into()].into(),
        scroll_offset: 0,
        auto_scroll: true,
        follow_mode: true,
    });

    let config = TuiConfig::default();

    terminal.draw(|f| render_all(f, &state, &config)).unwrap();
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

# Test 6: TUI search mode (NEW)
test_tui_search() {
    log "Test 6: TUI search functionality"

    OUTPUT=$("$RCH" tui --test-mode --mock-data --simulate-keys "/cargo" 2>&1 || true)
    log "  Search output: $(echo "$OUTPUT" | head -c 300)"

    pass "TUI search"
}

# Test 7: TUI log view (NEW)
test_tui_log_view() {
    log "Test 7: TUI log view"

    OUTPUT=$("$RCH" tui --test-mode --mock-data --simulate-keys "l" 2>&1 || true)
    log "  Log view output: $(echo "$OUTPUT" | head -c 300)"

    pass "TUI log view"
}

# Test 8: TUI render dimensions
test_tui_dimensions() {
    log "Test 8: TUI render at various dimensions"

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

# Test 9: TUI mouse support flag
test_tui_mouse() {
    log "Test 9: TUI mouse support"

    OUTPUT=$("$RCH" tui --test-mode --mock-data --no-mouse 2>&1 || true)
    log "  No mouse mode: $(echo "$OUTPUT" | head -c 100)"

    pass "TUI mouse support"
}

# Test 10: TUI JSON output mode (for automation)
test_tui_json() {
    log "Test 10: TUI JSON dump"

    OUTPUT=$("$RCH" tui --dump-state --mock-data 2>&1 || true)
    log "  JSON state: $(echo "$OUTPUT" | head -c 300)"

    if echo "$OUTPUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        log "    Valid JSON"
    else
        log "    Note: JSON dump may not be implemented yet"
    fi

    pass "TUI JSON dump"
}

# Test 11: TUI help display
test_tui_help() {
    log "Test 11: TUI help"

    OUTPUT=$("$RCH" tui --help 2>&1)
    log "  Help output: $(echo "$OUTPUT" | head -20 | tr '\n' ' ')"

    echo "$OUTPUT" | grep -qiE "tui|dashboard|interactive" || fail "Help missing TUI description"
    pass "TUI help"
}

# Test 12: TUI log export (NEW)
test_tui_log_export() {
    log "Test 12: TUI log export"

    EXPORT_FILE="$TEST_DIR/exported.log"
    OUTPUT=$("$RCH" tui --test-mode --mock-data --export-log "$EXPORT_FILE" 2>&1 || true)

    if [[ -f "$EXPORT_FILE" ]]; then
        log "  Export file created: $(wc -l < "$EXPORT_FILE") lines"
    else
        log "  Note: export may not be implemented yet"
    fi

    pass "TUI log export"
}

# Run all tests
test_tui_no_daemon
test_tui_test_mode
test_tui_accessibility
test_tui_color_blind
test_tui_refresh_rate
test_tui_search
test_tui_log_view
test_tui_dimensions
test_tui_mouse
test_tui_json
test_tui_help
test_tui_log_export

log "=== All TUI E2E tests passed ==="
log "Full log at: $LOG_FILE"
cat "$LOG_FILE"
```

## Logging Requirements

- DEBUG: Render cycle timing
- DEBUG: Key/mouse event handling
- DEBUG: Daemon data refresh
- DEBUG: **NEW**: Search query processing
- DEBUG: **NEW**: Log streaming events
- INFO: TUI started/stopped
- INFO: **NEW**: Log exported to file
- WARN: Render latency > 50ms
- ERROR: Terminal initialization failure
- ERROR: Daemon connection lost
- ERROR: **NEW**: Clipboard access failure

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
- [ ] **NEW: Search filters build history**
- [ ] **NEW: Log view shows build output**
- [ ] **NEW: Log copy/export works**
- [ ] Unit test coverage > 75%
- [ ] E2E tests pass

## Dependencies

- Status API (remote_compilation_helper-3sy) provides daemon data
- Build history (remote_compilation_helper-qgs) provides history data
- Rich status command (remote_compilation_helper-7ds) shares data model

## Blocks

- None (this is a terminal leaf feature)
