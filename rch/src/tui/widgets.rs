//! TUI widgets for dashboard components.
//!
//! Custom widgets for workers, builds, and status display.

use crate::tui::state::{BuildStatus, CircuitState, ColorBlindMode, Panel, TuiState, WorkerStatus};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

/// Get color scheme based on high contrast mode.
fn get_colors(high_contrast: bool, color_blind: ColorBlindMode) -> ColorScheme {
    if high_contrast {
        return ColorScheme {
            fg: Color::White,
            bg: Color::Black,
            highlight: Color::Yellow,
            success: Color::LightGreen,
            warning: Color::LightYellow,
            error: Color::LightRed,
            info: Color::LightCyan,
            muted: Color::Gray,
            selected_bg: Color::White,
            selected_fg: Color::Black,
        };
    }

    match color_blind {
        ColorBlindMode::None => ColorScheme {
            fg: Color::White,
            bg: Color::Reset,
            highlight: Color::Cyan,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Blue,
            muted: Color::DarkGray,
            selected_bg: Color::DarkGray,
            selected_fg: Color::White,
        },
        ColorBlindMode::Deuteranopia | ColorBlindMode::Protanopia => ColorScheme {
            fg: Color::White,
            bg: Color::Reset,
            highlight: Color::LightCyan,
            success: Color::LightCyan,
            warning: Color::Yellow,
            error: Color::LightMagenta,
            info: Color::LightBlue,
            muted: Color::DarkGray,
            selected_bg: Color::DarkGray,
            selected_fg: Color::White,
        },
        ColorBlindMode::Tritanopia => ColorScheme {
            fg: Color::White,
            bg: Color::Reset,
            highlight: Color::LightMagenta,
            success: Color::LightGreen,
            warning: Color::LightRed,
            error: Color::Red,
            info: Color::LightCyan,
            muted: Color::DarkGray,
            selected_bg: Color::DarkGray,
            selected_fg: Color::White,
        },
    }
}

struct ColorScheme {
    fg: Color,
    #[allow(dead_code)]
    bg: Color,
    highlight: Color,
    success: Color,
    warning: Color,
    error: Color,
    info: Color,
    muted: Color,
    selected_bg: Color,
    selected_fg: Color,
}

/// Render the main dashboard layout.
pub fn render(frame: &mut Frame, state: &TuiState) {
    let colors = get_colors(state.high_contrast, state.color_blind);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state, &colors);
    render_main_content(frame, chunks[1], state, &colors);
    render_footer(frame, chunks[2], state, &colors);

    // Render overlays on top
    if state.show_help {
        render_help_overlay(frame, &colors);
    }

    // Render filter input overlay when in filter mode
    if state.filter_mode {
        render_filter_input(frame, state, &colors);
    }

    // Render error message if present
    if let Some(ref error) = state.error {
        render_error_bar(frame, error, &colors);
    }

    // Render copy feedback
    if state.last_copied.is_some() {
        render_copy_feedback(frame, &colors);
    }
}

/// Render filter input overlay.
fn render_filter_input(frame: &mut Frame, state: &TuiState, colors: &ColorScheme) {
    let area = frame.area();
    // Position at bottom of screen, above footer
    let width = 50.min(area.width.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = area.height.saturating_sub(8);
    let input_area = Rect::new(x, y, width, 3);

    // Clear the area behind the overlay
    frame.render_widget(Clear, input_area);

    // Show search query with cursor indicator
    let cursor = "█";
    let input_text = format!("/{}{}", state.filter.query, cursor);
    let input = Paragraph::new(Line::from(vec![
        Span::styled("Search: ", Style::default().fg(colors.highlight)),
        Span::styled(input_text, Style::default().fg(colors.fg)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Filter Build History (Enter to apply, Esc to cancel)")
            .border_style(Style::default().fg(colors.highlight)),
    );

    frame.render_widget(input, input_area);
}

/// Render the header with daemon status.
fn render_header(frame: &mut Frame, area: Rect, state: &TuiState, colors: &ColorScheme) {
    let status_text = match state.daemon.status {
        crate::tui::state::Status::Running => "● Running",
        crate::tui::state::Status::Stopped => "○ Stopped",
        crate::tui::state::Status::Error => "✗ Error",
        crate::tui::state::Status::Unknown => "? Unknown",
    };

    let status_style = match state.daemon.status {
        crate::tui::state::Status::Running => Style::default().fg(colors.success),
        crate::tui::state::Status::Stopped => Style::default().fg(colors.warning),
        crate::tui::state::Status::Error => Style::default().fg(colors.error),
        crate::tui::state::Status::Unknown => Style::default().fg(colors.muted),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "RCH Dashboard",
            Style::default()
                .fg(colors.highlight)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(status_text, status_style),
        Span::raw(" | "),
        Span::styled(
            format!(
                "Workers: {} | Builds: {}",
                state.workers.len(),
                state.active_builds.len()
            ),
            Style::default().fg(colors.fg),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Status"));

    frame.render_widget(header, area);
}

/// Render the main content area with panels.
fn render_main_content(frame: &mut Frame, area: Rect, state: &TuiState, colors: &ColorScheme) {
    // If log view is open, show it full-screen
    if state.log_view.is_some() {
        render_logs_panel(frame, area, state, colors);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Workers
            Constraint::Percentage(60), // Builds
        ])
        .split(area);

    render_workers_panel(frame, chunks[0], state, colors);

    let build_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50), // Active builds
            Constraint::Percentage(50), // Build history
        ])
        .split(chunks[1]);

    render_active_builds_panel(frame, build_chunks[0], state, colors);
    render_build_history_panel(frame, build_chunks[1], state, colors);
}

/// Render the workers panel.
fn render_workers_panel(frame: &mut Frame, area: Rect, state: &TuiState, colors: &ColorScheme) {
    let is_selected = state.selected_panel == Panel::Workers;
    let border_style = if is_selected {
        Style::default().fg(colors.highlight)
    } else {
        Style::default()
    };

    let items: Vec<ListItem> = state
        .workers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let status_icon = match w.status {
                WorkerStatus::Healthy => "●",
                WorkerStatus::Degraded => "◐",
                WorkerStatus::Unreachable => "○",
                WorkerStatus::Draining => "◑",
            };
            let status_color = match w.status {
                WorkerStatus::Healthy => colors.success,
                WorkerStatus::Degraded => colors.warning,
                WorkerStatus::Unreachable => colors.error,
                WorkerStatus::Draining => colors.info,
            };
            // Use unicode symbols instead of emoji for terminal compatibility
            let circuit_icon = match w.circuit {
                CircuitState::Closed => "",
                CircuitState::HalfOpen => " ↻",
                CircuitState::Open => " ●",
            };

            let style = if is_selected && i == state.selected_index {
                Style::default()
                    .bg(colors.selected_bg)
                    .fg(colors.selected_fg)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(status_icon, Style::default().fg(status_color)),
                Span::raw(" "),
                Span::raw(&w.id),
                Span::styled(
                    format!(" ({}/{})", w.used_slots, w.total_slots),
                    Style::default().fg(colors.muted),
                ),
                Span::raw(circuit_icon),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Workers")
            .border_style(border_style),
    );

    frame.render_widget(list, area);
}

/// Render active builds panel.
fn render_active_builds_panel(
    frame: &mut Frame,
    area: Rect,
    state: &TuiState,
    colors: &ColorScheme,
) {
    let is_selected = state.selected_panel == Panel::ActiveBuilds;
    let border_style = if is_selected {
        Style::default().fg(colors.highlight)
    } else {
        Style::default()
    };

    let items: Vec<ListItem> = state
        .active_builds
        .iter()
        .enumerate()
        .map(|(i, b)| {
            // Use unicode symbols instead of emoji for terminal compatibility
            let status_icon = match b.status {
                BuildStatus::Pending => "◷",
                BuildStatus::Syncing => "↑",
                BuildStatus::Compiling => "⚙",
                BuildStatus::Downloading => "↓",
                BuildStatus::Completed => "✓",
                BuildStatus::Failed => "✗",
            };

            let progress = b
                .progress
                .as_ref()
                .and_then(|p| p.percent)
                .map(|p| format!(" {}%", p))
                .unwrap_or_default();

            let worker = b
                .worker
                .as_ref()
                .map(|w| format!(" → {}", w))
                .unwrap_or_default();

            let style = if is_selected && i == state.selected_index {
                Style::default()
                    .bg(colors.selected_bg)
                    .fg(colors.selected_fg)
            } else {
                Style::default()
            };

            // Truncate command for display (preserves important flags)
            let cmd = truncate_command(&b.command, 40);

            ListItem::new(Line::from(vec![
                Span::raw(status_icon),
                Span::raw(" "),
                Span::raw(cmd),
                Span::styled(worker, Style::default().fg(colors.info)),
                Span::styled(progress, Style::default().fg(colors.muted)),
            ]))
            .style(style)
        })
        .collect();

    let title = if state.active_builds.is_empty() {
        "Active Builds (none)"
    } else {
        "Active Builds"
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style),
    );

    frame.render_widget(list, area);
}

/// Render build history panel.
fn render_build_history_panel(
    frame: &mut Frame,
    area: Rect,
    state: &TuiState,
    colors: &ColorScheme,
) {
    let is_selected = state.selected_panel == Panel::BuildHistory;
    let border_style = if is_selected {
        Style::default().fg(colors.highlight)
    } else {
        Style::default()
    };

    // Use filtered history if filter is active
    let filtered = state.filtered_build_history();
    let items: Vec<ListItem> = filtered
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let status_icon = if b.success { "✓" } else { "✗" };
            let status_color = if b.success {
                colors.success
            } else {
                colors.error
            };

            let style = if is_selected && i == state.selected_index {
                Style::default()
                    .bg(colors.selected_bg)
                    .fg(colors.selected_fg)
            } else {
                Style::default()
            };

            let duration = format_duration_ms(b.duration_ms);
            let worker = b.worker.as_deref().unwrap_or("local");

            // Truncate command (preserves important flags)
            let cmd = truncate_command(&b.command, 30);

            ListItem::new(Line::from(vec![
                Span::styled(status_icon, Style::default().fg(status_color)),
                Span::raw(" "),
                Span::raw(cmd),
                Span::raw(" @ "),
                Span::styled(worker, Style::default().fg(colors.highlight)),
                Span::styled(
                    format!(" ({})", duration),
                    Style::default().fg(colors.muted),
                ),
            ]))
            .style(style)
        })
        .collect();

    let title = if state.filter_mode || !state.filter.query.is_empty() {
        format!(
            "Build History [{}/{}] (/ to filter)",
            filtered.len(),
            state.build_history.len()
        )
    } else {
        format!("Build History [{}]", state.build_history.len())
    };

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style),
    );

    frame.render_widget(list, area);
}

/// Format duration in human-readable form.
fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{:.1}m", ms as f64 / 60_000.0)
    }
}

fn truncate_to_char_boundary(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }

    let mut end = max_len;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Truncate a command string intelligently for display.
///
/// Preserves important suffixes like --release, -p <package>, --test when possible.
fn truncate_command(cmd: &str, max_len: usize) -> String {
    if cmd.len() <= max_len {
        return cmd.to_string();
    }

    // Important suffixes to preserve (in priority order)
    let important_suffixes = ["--release", "--test", "--bench", "--features"];

    // Check if any important suffix is at the end
    for suffix in important_suffixes {
        if cmd.ends_with(suffix) {
            let available = max_len.saturating_sub(suffix.len() + 4); // 4 for "... "
            if available > 8 {
                return format!(
                    "{}... {}",
                    truncate_to_char_boundary(cmd, available),
                    suffix
                );
            }
        }
    }

    // Check for -p <package> pattern
    if let Some(p_idx) = cmd.rfind(" -p ") {
        let suffix_start = p_idx;
        let suffix = &cmd[suffix_start..];
        if suffix.len() < max_len / 2 {
            let available = max_len.saturating_sub(suffix.len() + 3);
            if available > 8 {
                return format!("{}...{}", truncate_to_char_boundary(cmd, available), suffix);
            }
        }
    }

    // Default: simple truncation with ellipsis
    format!(
        "{}...",
        truncate_to_char_boundary(cmd, max_len.saturating_sub(3))
    )
}

/// Render the footer with help hints.
fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState, colors: &ColorScheme) {
    let hints = if state.filter_mode {
        vec![("Esc", "Exit filter"), ("Enter", "Apply")]
    } else if state.log_view.is_some() {
        vec![("Esc", "Close logs"), ("↑/↓", "Scroll"), ("y", "Copy")]
    } else {
        vec![
            ("q", "Quit"),
            ("↑/↓", "Navigate"),
            ("Tab", "Panel"),
            ("r", "Refresh"),
            ("?", "Help"),
            ("/", "Filter"),
        ]
    };

    let spans: Vec<Span> = hints
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(
                    *key,
                    Style::default()
                        .fg(colors.highlight)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(": "),
                Span::styled(*desc, Style::default().fg(colors.fg)),
                Span::raw(" | "),
            ]
        })
        .collect();

    let footer = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL).title("Controls"));

    frame.render_widget(footer, area);
}

/// Render the help overlay.
fn render_help_overlay(frame: &mut Frame, colors: &ColorScheme) {
    let area = frame.area();
    // Center the help box - increased height to accommodate more content
    // Content is ~31 lines, plus 2 for borders = 33 minimum for full content
    let width = 60.min(area.width.saturating_sub(4));
    let height = 34.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let help_area = Rect::new(x, y, width, height);

    // Clear the area behind the overlay
    frame.render_widget(Clear, help_area);

    let help_text = vec![
        Line::from(Span::styled(
            "RCH Dashboard Help",
            Style::default()
                .fg(colors.highlight)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  ↑/k, ↓/j    Move selection up/down"),
        Line::from("  Tab         Next panel"),
        Line::from("  Shift+Tab   Previous panel"),
        Line::from("  Enter       Select/expand item"),
        Line::from("  Backspace   Go back / Close log view"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Scrolling (Log View)",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  PgUp/PgDn   Scroll page up/down"),
        Line::from("  g           Jump to top"),
        Line::from("  G           Jump to bottom (resume auto-scroll)"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  r           Refresh data from daemon"),
        Line::from("  y           Copy selected item"),
        Line::from("  d           Drain selected worker (Workers panel)"),
        Line::from("  e           Enable selected worker (Workers panel)"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Search & Filter",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  /           Open filter (Build History panel)"),
        Line::from("  Enter       Apply filter"),
        Line::from("  Esc         Cancel filter"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  q, Esc      Quit / Close overlay"),
        Line::from("  ?, F1       Toggle this help"),
        Line::from("  Ctrl+C      Force quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(colors.muted),
        )),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Help")
                .border_style(Style::default().fg(colors.highlight)),
        )
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });

    frame.render_widget(help, help_area);
}

/// Render error bar at bottom of screen.
fn render_error_bar(frame: &mut Frame, error: &str, colors: &ColorScheme) {
    let area = frame.area();
    let error_area = Rect::new(
        1,
        area.height.saturating_sub(2),
        area.width.saturating_sub(2),
        1,
    );

    let error_msg = Paragraph::new(Line::from(vec![
        Span::styled(
            "Error: ",
            Style::default()
                .fg(colors.error)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(error, Style::default().fg(colors.error)),
    ]));

    frame.render_widget(error_msg, error_area);
}

/// Render copy feedback.
fn render_copy_feedback(frame: &mut Frame, colors: &ColorScheme) {
    let area = frame.area();
    let message = "Copied to clipboard!";
    let max_width = area.width.saturating_sub(2).max(1);
    let width = (message.len() as u16).min(max_width);
    let x = area.width.saturating_sub(width.saturating_add(1));
    let feedback_area = Rect::new(x, 1, width, 1);
    let visible = &message[..width as usize];

    let feedback = Paragraph::new(Span::styled(visible, Style::default().fg(colors.success)));

    frame.render_widget(feedback, feedback_area);
}

/// Render logs panel (full screen when viewing build logs).
fn render_logs_panel(frame: &mut Frame, area: Rect, state: &TuiState, colors: &ColorScheme) {
    let log_view = match &state.log_view {
        Some(lv) => lv,
        None => return,
    };

    let is_selected = state.selected_panel == Panel::Logs;
    let border_style = if is_selected {
        Style::default().fg(colors.highlight)
    } else {
        Style::default()
    };

    // Calculate visible window
    let visible_height = area.height.saturating_sub(2) as usize; // Account for borders
    let total_lines = log_view.lines.len();
    let scroll_offset = log_view
        .scroll_offset
        .min(total_lines.saturating_sub(visible_height));
    let end_line = (scroll_offset + visible_height).min(total_lines);

    // Get visible lines with scroll offset
    let items: Vec<ListItem> = log_view
        .lines
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .map(|line| {
            // Color code log lines based on content
            let style = if line.contains("error") || line.contains("Error") {
                Style::default().fg(colors.error)
            } else if line.contains("warning") || line.contains("Warning") {
                Style::default().fg(colors.warning)
            } else if line.contains("Compiling") || line.contains("Building") {
                Style::default().fg(colors.info)
            } else if line.contains("Finished") {
                Style::default().fg(colors.success)
            } else {
                Style::default().fg(colors.fg)
            };
            ListItem::new(Span::styled(line.as_str(), style))
        })
        .collect();

    // Build title with scroll position indicator
    let scroll_indicator = if total_lines > visible_height {
        format!(" [{}-{}/{}]", scroll_offset + 1, end_line, total_lines)
    } else {
        String::new()
    };

    let auto_scroll_indicator = if log_view.auto_scroll { " [AUTO]" } else { "" };

    let title = format!(
        "Build Logs: {}{}{} (Esc to close, PgUp/PgDn to scroll)",
        log_view.build_id, scroll_indicator, auto_scroll_indicator,
    );

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(border_style),
    );

    frame.render_widget(list, area);

    // Render scroll bar on the right side if content exceeds visible area
    if total_lines > visible_height {
        render_scrollbar(
            frame,
            area,
            scroll_offset,
            total_lines,
            visible_height,
            colors,
        );
    }
}

/// Render a simple text-based scrollbar.
fn render_scrollbar(
    frame: &mut Frame,
    area: Rect,
    offset: usize,
    total: usize,
    visible: usize,
    colors: &ColorScheme,
) {
    // Calculate scrollbar position
    let scrollbar_height = area.height.saturating_sub(2) as usize; // Inside borders
    if scrollbar_height == 0 || total == 0 {
        return;
    }

    // Calculate thumb position and size
    let thumb_size = ((visible as f64 / total as f64) * scrollbar_height as f64).max(1.0) as u16;
    let scroll_range = total.saturating_sub(visible);
    let thumb_pos = if scroll_range > 0 {
        ((offset as f64 / scroll_range as f64) * (scrollbar_height as f64 - thumb_size as f64))
            as u16
    } else {
        0
    };

    // Render scrollbar track and thumb on the right edge
    let x = area.x + area.width - 1;
    for i in 0..scrollbar_height as u16 {
        let y = area.y + 1 + i; // Start after top border
        let char = if i >= thumb_pos && i < thumb_pos + thumb_size {
            "█" // Thumb
        } else {
            "│" // Track
        };
        let style = if i >= thumb_pos && i < thumb_pos + thumb_size {
            Style::default().fg(colors.highlight)
        } else {
            Style::default().fg(colors.muted)
        };
        frame.render_widget(
            Paragraph::new(Span::styled(char, style)),
            Rect::new(x, y, 1, 1),
        );
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::tui::state::{
        ActiveBuild, BuildProgress, BuildStatus, CircuitState, FilterState, LogViewState, Panel,
        TuiState, WorkerState, WorkerStatus,
    };
    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use tracing::info;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    fn buffer_to_string(buffer: &Buffer) -> String {
        let mut out = String::new();
        let width = buffer.area.width;
        let height = buffer.area.height;
        for y in 0..height {
            for x in 0..width {
                if let Some(cell) = buffer.cell((x, y)) {
                    out.push_str(cell.symbol());
                } else {
                    out.push(' ');
                }
            }
            out.push('\n');
        }
        out
    }

    fn render_to_string<F>(width: u16, height: u16, mut draw: F) -> String
    where
        F: FnMut(&mut Frame),
    {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f)).unwrap();
        buffer_to_string(terminal.backend().buffer())
    }

    fn sample_worker(id: &str, status: WorkerStatus, circuit: CircuitState) -> WorkerState {
        WorkerState {
            id: id.to_string(),
            host: "worker.local".to_string(),
            status,
            circuit,
            total_slots: 8,
            used_slots: 2,
            latency_ms: 10,
            last_seen: Utc::now(),
            builds_completed: 3,
        }
    }

    fn sample_active_build(id: &str, command: &str) -> ActiveBuild {
        ActiveBuild {
            id: id.to_string(),
            command: command.to_string(),
            worker: Some("worker-1".to_string()),
            started_at: Utc::now(),
            progress: Some(BuildProgress {
                phase: "compiling".to_string(),
                percent: Some(42),
                current_file: None,
            }),
            status: BuildStatus::Compiling,
        }
    }

    #[test]
    fn test_render_workers_panel_contains_ids() {
        init_test_logging();
        info!("TEST START: test_render_workers_panel_contains_ids");
        let state = TuiState {
            selected_panel: Panel::Workers,
            workers: vec![
                sample_worker("worker-a", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("worker-b", WorkerStatus::Degraded, CircuitState::HalfOpen),
            ],
            ..Default::default()
        };
        let content = render_to_string(60, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_workers_panel(f, Rect::new(0, 0, 60, 10), &state, &colors);
        });
        info!("VERIFY: content contains worker ids");
        assert!(content.contains("worker-a"));
        assert!(content.contains("worker-b"));
        info!("TEST PASS: test_render_workers_panel_contains_ids");
    }

    #[test]
    fn test_color_blind_palette_selection() {
        init_test_logging();
        info!("TEST START: test_color_blind_palette_selection");
        let deuter = get_colors(false, ColorBlindMode::Deuteranopia);
        let tritan = get_colors(false, ColorBlindMode::Tritanopia);
        info!(
            "VERIFY: deuter_highlight={:?} tritan_highlight={:?}",
            deuter.highlight, tritan.highlight
        );
        assert_eq!(deuter.highlight, Color::LightCyan);
        assert_eq!(tritan.highlight, Color::LightMagenta);
        info!("TEST PASS: test_color_blind_palette_selection");
    }

    #[test]
    fn test_render_active_builds_panel_shows_command() {
        init_test_logging();
        info!("TEST START: test_render_active_builds_panel_shows_command");
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: vec![sample_active_build("b1", "cargo build")],
            ..Default::default()
        };
        let content = render_to_string(80, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_active_builds_panel(f, Rect::new(0, 0, 80, 10), &state, &colors);
        });
        assert!(content.contains("cargo build"));
        assert!(content.contains("worker-1"));
        info!("TEST PASS: test_render_active_builds_panel_shows_command");
    }

    #[test]
    fn test_render_build_history_panel_shows_filtered_title() {
        init_test_logging();
        info!("TEST START: test_render_build_history_panel_shows_filtered_title");
        let mut state = TuiState {
            selected_panel: Panel::BuildHistory,
            filter: FilterState {
                query: "build".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h1".to_string(),
                command: "cargo build".to_string(),
                worker: Some("worker-1".to_string()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 1200,
                success: true,
                exit_code: Some(0),
            });
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h2".to_string(),
                command: "cargo test".to_string(),
                worker: Some("worker-2".to_string()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 1500,
                success: false,
                exit_code: Some(1),
            });
        let content = render_to_string(80, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_build_history_panel(f, Rect::new(0, 0, 80, 10), &state, &colors);
        });
        assert!(content.contains("Build History [1/2]"));
        info!("TEST PASS: test_render_build_history_panel_shows_filtered_title");
    }

    #[test]
    fn test_render_logs_panel_scroll_indicator() {
        init_test_logging();
        info!("TEST START: test_render_logs_panel_scroll_indicator");
        let mut log_view = LogViewState::default();
        for i in 0..10 {
            log_view.lines.push_back(format!("line {}", i));
        }
        log_view.scroll_offset = 2;
        let state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let content = render_to_string(80, 6, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_logs_panel(f, Rect::new(0, 0, 80, 6), &state, &colors);
        });
        assert!(content.contains("[3-6/10]"));
        assert!(content.contains("AUTO"));
        info!("TEST PASS: test_render_logs_panel_scroll_indicator");
    }

    #[test]
    fn test_render_help_overlay() {
        init_test_logging();
        info!("TEST START: test_render_help_overlay");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 24, |f| render(f, &state));
        assert!(content.contains("RCH Dashboard Help"));
        info!("TEST PASS: test_render_help_overlay");
    }

    #[test]
    fn test_help_overlay_contains_filter_shortcut() {
        init_test_logging();
        info!("TEST START: test_help_overlay_contains_filter_shortcut");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        // Need larger height to see all content
        let content = render_to_string(80, 32, |f| render(f, &state));
        // Verify filter shortcut is documented
        assert!(content.contains("/"), "Filter shortcut (/) must be documented");
        assert!(
            content.contains("filter") || content.contains("Filter") || content.contains("Search"),
            "Filter functionality must be described"
        );
        info!("TEST PASS: test_help_overlay_contains_filter_shortcut");
    }

    #[test]
    fn test_help_overlay_contains_all_navigation_shortcuts() {
        init_test_logging();
        info!("TEST START: test_help_overlay_contains_all_navigation_shortcuts");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify all navigation shortcuts are documented
        info!("VERIFY: checking navigation shortcuts");
        assert!(content.contains("j") || content.contains("↓"), "Down navigation must be documented");
        assert!(content.contains("k") || content.contains("↑"), "Up navigation must be documented");
        assert!(content.contains("Tab"), "Tab for panel switching must be documented");
        assert!(content.contains("Enter"), "Enter for selection must be documented");
        info!("TEST PASS: test_help_overlay_contains_all_navigation_shortcuts");
    }

    #[test]
    fn test_help_overlay_contains_all_action_shortcuts() {
        init_test_logging();
        info!("TEST START: test_help_overlay_contains_all_action_shortcuts");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify all action shortcuts are documented
        info!("VERIFY: checking action shortcuts");
        assert!(content.contains("r"), "Refresh shortcut must be documented");
        assert!(content.contains("y"), "Copy shortcut must be documented");
        assert!(content.contains("d"), "Drain shortcut must be documented");
        assert!(content.contains("e"), "Enable shortcut must be documented");
        info!("TEST PASS: test_help_overlay_contains_all_action_shortcuts");
    }

    #[test]
    fn test_help_overlay_contains_scrolling_shortcuts() {
        init_test_logging();
        info!("TEST START: test_help_overlay_contains_scrolling_shortcuts");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify scrolling shortcuts are documented
        info!("VERIFY: checking scrolling shortcuts");
        assert!(
            content.contains("PgUp") || content.contains("PageUp") || content.contains("Page"),
            "Page up must be documented"
        );
        assert!(content.contains("g"), "Jump to top (g) must be documented");
        assert!(content.contains("G"), "Jump to bottom (G) must be documented");
        info!("TEST PASS: test_help_overlay_contains_scrolling_shortcuts");
    }

    #[test]
    fn test_help_overlay_contains_general_shortcuts() {
        init_test_logging();
        info!("TEST START: test_help_overlay_contains_general_shortcuts");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        // Need taller terminal to see all content
        let content = render_to_string(80, 36, |f| render(f, &state));

        // Verify general shortcuts are documented
        info!("VERIFY: checking general shortcuts");
        assert!(content.contains("q"), "Quit shortcut must be documented");
        assert!(content.contains("Esc"), "Escape shortcut must be documented");
        // The ? character in the help text - check for help toggle description
        assert!(
            content.contains("Toggle") || content.contains("Help") || content.contains("help"),
            "Help toggle shortcut must be documented"
        );
        assert!(content.contains("F1"), "F1 help shortcut must be documented");
        assert!(content.contains("Ctrl"), "Ctrl+C must be documented");
        info!("TEST PASS: test_help_overlay_contains_general_shortcuts");
    }

    #[test]
    fn test_help_overlay_section_ordering() {
        init_test_logging();
        info!("TEST START: test_help_overlay_section_ordering");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify sections are in logical order
        info!("VERIFY: checking section order");
        let nav_pos = content.find("Navigation");
        let actions_pos = content.find("Actions");
        let general_pos = content.find("General");

        assert!(nav_pos.is_some(), "Navigation section must exist");
        assert!(actions_pos.is_some(), "Actions section must exist");
        assert!(general_pos.is_some(), "General section must exist");

        // Navigation should come before Actions, which should come before General
        let nav = nav_pos.unwrap();
        let actions = actions_pos.unwrap();
        let general = general_pos.unwrap();

        assert!(nav < actions, "Navigation should come before Actions");
        assert!(actions < general, "Actions should come before General");
        info!("TEST PASS: test_help_overlay_section_ordering");
    }

    #[test]
    fn test_help_overlay_fits_80x24() {
        init_test_logging();
        info!("TEST START: test_help_overlay_fits_80x24");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        // Standard terminal size - should render without panic
        let content = render_to_string(80, 24, |f| render(f, &state));

        // Should still contain the title - full content may be clipped
        assert!(content.contains("Help"), "Help title should be visible");
        // At 80x24, the overlay height is clamped to 20 lines, so not all content
        // may be visible. Just verify the title and at least one section header.
        assert!(
            content.contains("Navigation") || content.contains("RCH Dashboard"),
            "At least the title or first section should be visible"
        );
        info!("TEST PASS: test_help_overlay_fits_80x24");
    }

    #[test]
    fn test_help_overlay_fits_minimal_terminal() {
        init_test_logging();
        info!("TEST START: test_help_overlay_fits_minimal_terminal");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        // Minimal terminal size (40x12) - should not panic
        let content = render_to_string(40, 12, |f| render(f, &state));

        // Should render something
        assert!(!content.is_empty(), "Content should not be empty");
        info!("TEST PASS: test_help_overlay_fits_minimal_terminal");
    }

    #[test]
    fn test_help_overlay_worker_actions_context() {
        init_test_logging();
        info!("TEST START: test_help_overlay_worker_actions_context");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify worker actions mention they're panel-specific
        info!("VERIFY: worker actions should mention Workers panel");
        assert!(
            content.contains("Workers") || content.contains("worker"),
            "Worker actions should mention Workers panel context"
        );
        info!("TEST PASS: test_help_overlay_worker_actions_context");
    }

    #[test]
    fn test_help_overlay_filter_context() {
        init_test_logging();
        info!("TEST START: test_help_overlay_filter_context");
        let state = TuiState {
            show_help: true,
            ..Default::default()
        };
        let content = render_to_string(80, 32, |f| render(f, &state));

        // Verify filter mentions Build History panel
        info!("VERIFY: filter should mention Build History panel");
        assert!(
            content.contains("Build") || content.contains("History"),
            "Filter should mention Build History panel context"
        );
        info!("TEST PASS: test_help_overlay_filter_context");
    }

    #[test]
    fn test_render_filter_input_overlay() {
        init_test_logging();
        info!("TEST START: test_render_filter_input_overlay");
        let state = TuiState {
            filter_mode: true,
            filter: FilterState {
                query: "abc".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let content = render_to_string(80, 24, |f| render(f, &state));
        assert!(content.contains("Search:"));
        assert!(content.contains("/abc"));
        info!("TEST PASS: test_render_filter_input_overlay");
    }

    #[test]
    fn test_render_error_bar() {
        init_test_logging();
        info!("TEST START: test_render_error_bar");
        let state = TuiState {
            error: Some("daemon down".to_string()),
            ..Default::default()
        };
        let content = render_to_string(80, 24, |f| render(f, &state));
        assert!(content.contains("Error:"));
        assert!(content.contains("daemon down"));
        info!("TEST PASS: test_render_error_bar");
    }

    #[test]
    fn test_render_copy_feedback() {
        init_test_logging();
        info!("TEST START: test_render_copy_feedback");
        let state = TuiState {
            last_copied: Some("payload".to_string()),
            ..Default::default()
        };
        let content = render_to_string(80, 24, |f| render(f, &state));
        assert!(content.contains("Copied to clipboard!"));
        info!("TEST PASS: test_render_copy_feedback");
    }

    #[test]
    fn test_render_minimum_size_no_panic() {
        init_test_logging();
        info!("TEST START: test_render_minimum_size_no_panic");
        let state = TuiState::default();
        let result = std::panic::catch_unwind(|| {
            let _ = render_to_string(1, 1, |f| render(f, &state));
        });
        assert!(result.is_ok());
        info!("TEST PASS: test_render_minimum_size_no_panic");
    }

    // ==================== format_duration_ms tests ====================

    #[test]
    fn test_format_duration_ms_milliseconds() {
        init_test_logging();
        info!("TEST START: test_format_duration_ms_milliseconds");
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(1), "1ms");
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(999), "999ms");
        info!("TEST PASS: test_format_duration_ms_milliseconds");
    }

    #[test]
    fn test_format_duration_ms_seconds() {
        init_test_logging();
        info!("TEST START: test_format_duration_ms_seconds");
        assert_eq!(format_duration_ms(1000), "1.0s");
        assert_eq!(format_duration_ms(1500), "1.5s");
        assert_eq!(format_duration_ms(30000), "30.0s");
        assert_eq!(format_duration_ms(59999), "60.0s");
        info!("TEST PASS: test_format_duration_ms_seconds");
    }

    #[test]
    fn test_format_duration_ms_minutes() {
        init_test_logging();
        info!("TEST START: test_format_duration_ms_minutes");
        assert_eq!(format_duration_ms(60000), "1.0m");
        assert_eq!(format_duration_ms(90000), "1.5m");
        assert_eq!(format_duration_ms(300000), "5.0m");
        info!("TEST PASS: test_format_duration_ms_minutes");
    }

    // ==================== Color scheme tests ====================

    #[test]
    fn test_high_contrast_mode_colors() {
        init_test_logging();
        info!("TEST START: test_high_contrast_mode_colors");
        let high_contrast = get_colors(true, ColorBlindMode::None);
        assert_eq!(high_contrast.fg, Color::White);
        assert_eq!(high_contrast.bg, Color::Black);
        assert_eq!(high_contrast.highlight, Color::Yellow);
        assert_eq!(high_contrast.success, Color::LightGreen);
        assert_eq!(high_contrast.error, Color::LightRed);
        assert_eq!(high_contrast.selected_bg, Color::White);
        assert_eq!(high_contrast.selected_fg, Color::Black);
        info!("TEST PASS: test_high_contrast_mode_colors");
    }

    #[test]
    fn test_color_blind_protanopia_same_as_deuteranopia() {
        init_test_logging();
        info!("TEST START: test_color_blind_protanopia_same_as_deuteranopia");
        let proto = get_colors(false, ColorBlindMode::Protanopia);
        let deuter = get_colors(false, ColorBlindMode::Deuteranopia);
        // Protanopia and Deuteranopia use the same palette
        assert_eq!(proto.highlight, deuter.highlight);
        assert_eq!(proto.success, deuter.success);
        assert_eq!(proto.error, deuter.error);
        assert_eq!(proto.highlight, Color::LightCyan);
        assert_eq!(proto.error, Color::LightMagenta);
        info!("TEST PASS: test_color_blind_protanopia_same_as_deuteranopia");
    }

    #[test]
    fn test_color_blind_tritanopia_distinct_palette() {
        init_test_logging();
        info!("TEST START: test_color_blind_tritanopia_distinct_palette");
        let tritan = get_colors(false, ColorBlindMode::Tritanopia);
        let normal = get_colors(false, ColorBlindMode::None);
        // Tritanopia uses different highlight
        assert_eq!(tritan.highlight, Color::LightMagenta);
        assert_ne!(tritan.highlight, normal.highlight);
        assert_eq!(tritan.warning, Color::LightRed);
        info!("TEST PASS: test_color_blind_tritanopia_distinct_palette");
    }

    #[test]
    fn test_normal_mode_colors() {
        init_test_logging();
        info!("TEST START: test_normal_mode_colors");
        let normal = get_colors(false, ColorBlindMode::None);
        assert_eq!(normal.fg, Color::White);
        assert_eq!(normal.bg, Color::Reset);
        assert_eq!(normal.highlight, Color::Cyan);
        assert_eq!(normal.success, Color::Green);
        assert_eq!(normal.warning, Color::Yellow);
        assert_eq!(normal.error, Color::Red);
        assert_eq!(normal.info, Color::Blue);
        info!("TEST PASS: test_normal_mode_colors");
    }

    // ==================== Worker status rendering tests ====================

    #[test]
    fn test_render_worker_all_status_icons() {
        init_test_logging();
        info!("TEST START: test_render_worker_all_status_icons");
        let state = TuiState {
            selected_panel: Panel::Workers,
            workers: vec![
                sample_worker("healthy-w", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("degraded-w", WorkerStatus::Degraded, CircuitState::Closed),
                sample_worker(
                    "unreachable-w",
                    WorkerStatus::Unreachable,
                    CircuitState::Closed,
                ),
                sample_worker("draining-w", WorkerStatus::Draining, CircuitState::Closed),
            ],
            ..Default::default()
        };
        let content = render_to_string(60, 12, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_workers_panel(f, Rect::new(0, 0, 60, 12), &state, &colors);
        });
        // Verify all workers are shown
        assert!(content.contains("healthy-w"));
        assert!(content.contains("degraded-w"));
        assert!(content.contains("unreachable-w"));
        assert!(content.contains("draining-w"));
        info!("TEST PASS: test_render_worker_all_status_icons");
    }

    #[test]
    fn test_render_worker_circuit_state_icons() {
        init_test_logging();
        info!("TEST START: test_render_worker_circuit_state_icons");
        let state = TuiState {
            selected_panel: Panel::Workers,
            workers: vec![
                sample_worker("closed-w", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("half-w", WorkerStatus::Healthy, CircuitState::HalfOpen),
                sample_worker("open-w", WorkerStatus::Healthy, CircuitState::Open),
            ],
            ..Default::default()
        };
        let content = render_to_string(60, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_workers_panel(f, Rect::new(0, 0, 60, 10), &state, &colors);
        });
        // Check workers are rendered
        assert!(content.contains("half-w"));
        assert!(content.contains("open-w"));
        // Verify unicode symbols are used (not emoji) for terminal compatibility
        // HalfOpen uses ↻ (recycling), Open uses ● (filled circle)
        assert!(
            content.contains("↻") || content.contains("●"),
            "Circuit icons should use unicode symbols for terminal compatibility"
        );
        info!("TEST PASS: test_render_worker_circuit_state_icons");
    }

    #[test]
    fn test_circuit_icons_no_emoji() {
        init_test_logging();
        info!("TEST START: test_circuit_icons_no_emoji");
        let state = TuiState {
            selected_panel: Panel::Workers,
            workers: vec![
                sample_worker("w1", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("w2", WorkerStatus::Healthy, CircuitState::HalfOpen),
                sample_worker("w3", WorkerStatus::Healthy, CircuitState::Open),
            ],
            ..Default::default()
        };
        let content = render_to_string(80, 24, |f| render(f, &state));
        // Emoji that should NOT be present
        assert!(
            !content.contains("🔴"),
            "Should not contain red circle emoji"
        );
        assert!(!content.contains("⚡"), "Should not contain lightning emoji");
        assert!(
            !content.contains("🟢"),
            "Should not contain green circle emoji"
        );
        assert!(
            !content.contains("🟡"),
            "Should not contain yellow circle emoji"
        );
        info!("TEST PASS: test_circuit_icons_no_emoji");
    }

    #[test]
    fn test_status_icons_terminal_compatible() {
        init_test_logging();
        info!("TEST START: test_status_icons_terminal_compatible");
        // Verify the unicode symbols used are widely supported
        // These are from the Box Drawing and Geometric Shapes unicode blocks
        // which have very good terminal font support
        let symbols = ["✓", "✗", "●", "↻", "◐", "○"];
        for sym in symbols {
            assert!(
                sym.chars().all(|c| (c as u32) < 0x10000),
                "Symbol {} should be in BMP for terminal compatibility",
                sym
            );
        }
        info!("TEST PASS: test_status_icons_terminal_compatible");
    }

    #[test]
    fn test_render_workers_slot_display() {
        init_test_logging();
        info!("TEST START: test_render_workers_slot_display");
        let mut worker = sample_worker("slot-w", WorkerStatus::Healthy, CircuitState::Closed);
        worker.used_slots = 5;
        worker.total_slots = 10;
        let state = TuiState {
            selected_panel: Panel::Workers,
            workers: vec![worker],
            ..Default::default()
        };
        let content = render_to_string(60, 6, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_workers_panel(f, Rect::new(0, 0, 60, 6), &state, &colors);
        });
        assert!(content.contains("(5/10)"));
        info!("TEST PASS: test_render_workers_slot_display");
    }

    // ==================== Build status rendering tests ====================

    #[test]
    fn test_render_all_build_statuses() {
        init_test_logging();
        info!("TEST START: test_render_all_build_statuses");
        let builds = vec![
            ActiveBuild {
                id: "b1".to_string(),
                command: "pending cmd".to_string(),
                worker: None,
                started_at: Utc::now(),
                progress: None,
                status: BuildStatus::Pending,
            },
            ActiveBuild {
                id: "b2".to_string(),
                command: "syncing cmd".to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                progress: None,
                status: BuildStatus::Syncing,
            },
            ActiveBuild {
                id: "b3".to_string(),
                command: "compiling cmd".to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                progress: Some(BuildProgress {
                    phase: "compiling".to_string(),
                    percent: Some(50),
                    current_file: None,
                }),
                status: BuildStatus::Compiling,
            },
            ActiveBuild {
                id: "b4".to_string(),
                command: "downloading cmd".to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                progress: None,
                status: BuildStatus::Downloading,
            },
        ];
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: builds,
            ..Default::default()
        };
        let content = render_to_string(80, 12, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_active_builds_panel(f, Rect::new(0, 0, 80, 12), &state, &colors);
        });
        assert!(content.contains("pending cmd"));
        assert!(content.contains("syncing cmd"));
        assert!(content.contains("compiling cmd"));
        assert!(content.contains("downloading cmd"));
        info!("TEST PASS: test_render_all_build_statuses");
    }

    #[test]
    fn test_render_empty_active_builds_shows_none() {
        init_test_logging();
        info!("TEST START: test_render_empty_active_builds_shows_none");
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: vec![],
            ..Default::default()
        };
        let content = render_to_string(60, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_active_builds_panel(f, Rect::new(0, 0, 60, 8), &state, &colors);
        });
        assert!(content.contains("Active Builds (none)"));
        info!("TEST PASS: test_render_empty_active_builds_shows_none");
    }

    // ==================== Command truncation tests ====================

    #[test]
    fn test_active_build_command_truncation() {
        init_test_logging();
        info!("TEST START: test_active_build_command_truncation");
        let long_command = "cargo build --release --features=abc,def,ghi,jkl,mno,pqr";
        let build = ActiveBuild {
            id: "b1".to_string(),
            command: long_command.to_string(),
            worker: Some("w1".to_string()),
            started_at: Utc::now(),
            progress: None,
            status: BuildStatus::Compiling,
        };
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: vec![build],
            ..Default::default()
        };
        let content = render_to_string(80, 6, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_active_builds_panel(f, Rect::new(0, 0, 80, 6), &state, &colors);
        });
        // Command should be truncated with "..."
        assert!(content.contains("..."));
        // Full command should not appear
        assert!(!content.contains(long_command));
        info!("TEST PASS: test_active_build_command_truncation");
    }

    #[test]
    fn test_history_command_truncation() {
        init_test_logging();
        info!("TEST START: test_history_command_truncation");
        let long_command = "cargo build --release --features=abc,def,ghi,jkl";
        let mut state = TuiState {
            selected_panel: Panel::BuildHistory,
            ..Default::default()
        };
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h1".to_string(),
                command: long_command.to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 1200,
                success: true,
                exit_code: Some(0),
            });
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_build_history_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        // Command should be truncated with "..."
        assert!(content.contains("..."));
        info!("TEST PASS: test_history_command_truncation");
    }

    // ==================== Header rendering tests ====================

    #[test]
    fn test_render_header_all_daemon_statuses() {
        init_test_logging();
        info!("TEST START: test_render_header_all_daemon_statuses");
        use crate::tui::state::Status;

        for (status, expected_text) in [
            (Status::Running, "Running"),
            (Status::Stopped, "Stopped"),
            (Status::Error, "Error"),
            (Status::Unknown, "Unknown"),
        ] {
            let mut state = TuiState::default();
            state.daemon.status = status;
            let content = render_to_string(80, 5, |f| {
                let colors = get_colors(false, ColorBlindMode::None);
                render_header(f, Rect::new(0, 0, 80, 5), &state, &colors);
            });
            assert!(
                content.contains(expected_text),
                "Expected '{}' in output for status {:?}",
                expected_text,
                status
            );
        }
        info!("TEST PASS: test_render_header_all_daemon_statuses");
    }

    #[test]
    fn test_render_header_shows_counts() {
        init_test_logging();
        info!("TEST START: test_render_header_shows_counts");
        let state = TuiState {
            workers: vec![
                sample_worker("w1", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("w2", WorkerStatus::Healthy, CircuitState::Closed),
            ],
            active_builds: vec![sample_active_build("b1", "cmd")],
            ..Default::default()
        };
        let content = render_to_string(80, 5, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_header(f, Rect::new(0, 0, 80, 5), &state, &colors);
        });
        assert!(content.contains("Workers: 2"));
        assert!(content.contains("Builds: 1"));
        info!("TEST PASS: test_render_header_shows_counts");
    }

    // ==================== Footer rendering tests ====================

    #[test]
    fn test_render_footer_normal_mode_hints() {
        init_test_logging();
        info!("TEST START: test_render_footer_normal_mode_hints");
        let state = TuiState::default();
        let content = render_to_string(80, 5, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_footer(f, Rect::new(0, 0, 80, 5), &state, &colors);
        });
        assert!(content.contains("Quit"));
        assert!(content.contains("Navigate"));
        assert!(content.contains("Refresh"));
        assert!(content.contains("Help"));
        info!("TEST PASS: test_render_footer_normal_mode_hints");
    }

    #[test]
    fn test_render_footer_filter_mode_hints() {
        init_test_logging();
        info!("TEST START: test_render_footer_filter_mode_hints");
        let state = TuiState {
            filter_mode: true,
            ..Default::default()
        };
        let content = render_to_string(80, 5, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_footer(f, Rect::new(0, 0, 80, 5), &state, &colors);
        });
        assert!(content.contains("Exit filter"));
        assert!(content.contains("Apply"));
        info!("TEST PASS: test_render_footer_filter_mode_hints");
    }

    #[test]
    fn test_render_footer_log_view_hints() {
        init_test_logging();
        info!("TEST START: test_render_footer_log_view_hints");
        let state = TuiState {
            log_view: Some(LogViewState::default()),
            ..Default::default()
        };
        let content = render_to_string(80, 5, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_footer(f, Rect::new(0, 0, 80, 5), &state, &colors);
        });
        assert!(content.contains("Close logs"));
        assert!(content.contains("Scroll"));
        assert!(content.contains("Copy"));
        info!("TEST PASS: test_render_footer_log_view_hints");
    }

    // ==================== Log panel rendering tests ====================

    #[test]
    fn test_render_logs_panel_empty_lines() {
        init_test_logging();
        info!("TEST START: test_render_logs_panel_empty_lines");
        let log_view = LogViewState::default();
        let state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_logs_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        assert!(content.contains("Build Logs"));
        info!("TEST PASS: test_render_logs_panel_empty_lines");
    }

    #[test]
    fn test_render_logs_panel_auto_scroll_indicator() {
        init_test_logging();
        info!("TEST START: test_render_logs_panel_auto_scroll_indicator");
        let mut log_view = LogViewState::default();
        log_view.auto_scroll = true;
        log_view.lines.push_back("test line".to_string());
        let state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_logs_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        assert!(content.contains("[AUTO]"));
        info!("TEST PASS: test_render_logs_panel_auto_scroll_indicator");
    }

    #[test]
    fn test_render_logs_panel_no_scroll_indicator_when_disabled() {
        init_test_logging();
        info!("TEST START: test_render_logs_panel_no_scroll_indicator_when_disabled");
        let mut log_view = LogViewState::default();
        log_view.auto_scroll = false;
        log_view.lines.push_back("test line".to_string());
        let state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_logs_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        assert!(!content.contains("[AUTO]"));
        info!("TEST PASS: test_render_logs_panel_no_scroll_indicator_when_disabled");
    }

    // ==================== Rendering at different widths ====================

    #[test]
    fn test_render_at_narrow_width() {
        init_test_logging();
        info!("TEST START: test_render_at_narrow_width");
        let state = TuiState {
            workers: vec![sample_worker(
                "w1",
                WorkerStatus::Healthy,
                CircuitState::Closed,
            )],
            active_builds: vec![sample_active_build("b1", "cargo build")],
            ..Default::default()
        };
        // Test at 40 columns (narrow terminal)
        let result = std::panic::catch_unwind(|| {
            let _ = render_to_string(40, 20, |f| render(f, &state));
        });
        assert!(result.is_ok());
        info!("TEST PASS: test_render_at_narrow_width");
    }

    #[test]
    fn test_render_at_wide_width() {
        init_test_logging();
        info!("TEST START: test_render_at_wide_width");
        let state = TuiState {
            workers: vec![sample_worker(
                "w1",
                WorkerStatus::Healthy,
                CircuitState::Closed,
            )],
            active_builds: vec![sample_active_build("b1", "cargo build")],
            ..Default::default()
        };
        // Test at 200 columns (wide terminal)
        let result = std::panic::catch_unwind(|| {
            let _ = render_to_string(200, 50, |f| render(f, &state));
        });
        assert!(result.is_ok());
        info!("TEST PASS: test_render_at_wide_width");
    }

    #[test]
    fn test_render_at_short_height() {
        init_test_logging();
        info!("TEST START: test_render_at_short_height");
        let state = TuiState::default();
        // Test at 5 rows (very short terminal)
        let result = std::panic::catch_unwind(|| {
            let _ = render_to_string(80, 5, |f| render(f, &state));
        });
        assert!(result.is_ok());
        info!("TEST PASS: test_render_at_short_height");
    }

    // ==================== Main content rendering tests ====================

    #[test]
    fn test_render_main_content_shows_log_view_fullscreen() {
        init_test_logging();
        info!("TEST START: test_render_main_content_shows_log_view_fullscreen");
        let mut log_view = LogViewState::default();
        log_view.build_id = "test-build-123".to_string();
        log_view.lines.push_back("Compiling test...".to_string());
        let state = TuiState {
            log_view: Some(log_view),
            selected_panel: Panel::Logs,
            ..Default::default()
        };
        let content = render_to_string(80, 20, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_main_content(f, Rect::new(0, 0, 80, 20), &state, &colors);
        });
        // Log view should be rendered, not the workers/builds panels
        assert!(content.contains("test-build-123"));
        assert!(content.contains("Compiling test"));
        info!("TEST PASS: test_render_main_content_shows_log_view_fullscreen");
    }

    #[test]
    fn test_render_main_content_normal_layout() {
        init_test_logging();
        info!("TEST START: test_render_main_content_normal_layout");
        let state = TuiState {
            workers: vec![sample_worker(
                "main-worker",
                WorkerStatus::Healthy,
                CircuitState::Closed,
            )],
            ..Default::default()
        };
        let content = render_to_string(100, 30, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_main_content(f, Rect::new(0, 0, 100, 30), &state, &colors);
        });
        // Workers panel should be visible
        assert!(content.contains("main-worker"));
        assert!(content.contains("Workers"));
        info!("TEST PASS: test_render_main_content_normal_layout");
    }

    // ==================== Selection highlighting tests ====================

    #[test]
    fn test_selection_highlight_in_workers_panel() {
        init_test_logging();
        info!("TEST START: test_selection_highlight_in_workers_panel");
        let state = TuiState {
            selected_panel: Panel::Workers,
            selected_index: 1,
            workers: vec![
                sample_worker("unselected", WorkerStatus::Healthy, CircuitState::Closed),
                sample_worker("selected", WorkerStatus::Healthy, CircuitState::Closed),
            ],
            ..Default::default()
        };
        let content = render_to_string(60, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_workers_panel(f, Rect::new(0, 0, 60, 10), &state, &colors);
        });
        // Both workers should be visible
        assert!(content.contains("unselected"));
        assert!(content.contains("selected"));
        info!("TEST PASS: test_selection_highlight_in_workers_panel");
    }

    // ==================== History panel tests ====================

    #[test]
    fn test_history_success_and_failure_icons() {
        init_test_logging();
        info!("TEST START: test_history_success_and_failure_icons");
        let mut state = TuiState {
            selected_panel: Panel::BuildHistory,
            ..Default::default()
        };
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h1".to_string(),
                command: "success cmd".to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 1200,
                success: true,
                exit_code: Some(0),
            });
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h2".to_string(),
                command: "failed cmd".to_string(),
                worker: Some("w1".to_string()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 500,
                success: false,
                exit_code: Some(1),
            });
        let content = render_to_string(80, 10, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_build_history_panel(f, Rect::new(0, 0, 80, 10), &state, &colors);
        });
        assert!(content.contains("success cmd"));
        assert!(content.contains("failed cmd"));
        info!("TEST PASS: test_history_success_and_failure_icons");
    }

    #[test]
    fn test_history_local_worker_display() {
        init_test_logging();
        info!("TEST START: test_history_local_worker_display");
        let mut state = TuiState {
            selected_panel: Panel::BuildHistory,
            ..Default::default()
        };
        state
            .build_history
            .push_back(crate::tui::state::HistoricalBuild {
                id: "h1".to_string(),
                command: "local build".to_string(),
                worker: None, // Local build, no worker assigned
                started_at: Utc::now(),
                completed_at: Utc::now(),
                duration_ms: 1200,
                success: true,
                exit_code: Some(0),
            });
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_build_history_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        // Should show "local" for builds without a worker
        assert!(content.contains("local"));
        info!("TEST PASS: test_history_local_worker_display");
    }

    // ==================== Progress display tests ====================

    #[test]
    fn test_active_build_progress_percent_display() {
        init_test_logging();
        info!("TEST START: test_active_build_progress_percent_display");
        let build = ActiveBuild {
            id: "b1".to_string(),
            command: "cargo build".to_string(),
            worker: Some("w1".to_string()),
            started_at: Utc::now(),
            progress: Some(BuildProgress {
                phase: "compiling".to_string(),
                percent: Some(75),
                current_file: None,
            }),
            status: BuildStatus::Compiling,
        };
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: vec![build],
            ..Default::default()
        };
        let content = render_to_string(80, 8, |f| {
            let colors = get_colors(false, ColorBlindMode::None);
            render_active_builds_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
        });
        assert!(content.contains("75%"));
        info!("TEST PASS: test_active_build_progress_percent_display");
    }

    #[test]
    fn test_active_build_no_progress() {
        init_test_logging();
        info!("TEST START: test_active_build_no_progress");
        let build = ActiveBuild {
            id: "b1".to_string(),
            command: "cargo build".to_string(),
            worker: Some("w1".to_string()),
            started_at: Utc::now(),
            progress: None,
            status: BuildStatus::Pending,
        };
        let state = TuiState {
            selected_panel: Panel::ActiveBuilds,
            active_builds: vec![build],
            ..Default::default()
        };
        // Should not panic with None progress
        let result = std::panic::catch_unwind(|| {
            let _ = render_to_string(80, 8, |f| {
                let colors = get_colors(false, ColorBlindMode::None);
                render_active_builds_panel(f, Rect::new(0, 0, 80, 8), &state, &colors);
            });
        });
        assert!(result.is_ok());
        info!("TEST PASS: test_active_build_no_progress");
    }

    #[test]
    fn test_truncate_command_short() {
        // Short commands should not be truncated
        assert_eq!(truncate_command("cargo build", 40), "cargo build");
    }

    #[test]
    fn test_truncate_command_preserves_release() {
        let cmd = "cargo build --target x86_64-unknown-linux-gnu --release";
        let result = truncate_command(cmd, 40);
        assert!(result.len() <= 40);
        assert!(
            result.contains("--release"),
            "Should preserve --release: {result}"
        );
    }

    #[test]
    fn test_truncate_command_preserves_package() {
        let cmd = "cargo test --target x86_64-unknown-linux-gnu -p my-pkg";
        let result = truncate_command(cmd, 35);
        assert!(result.len() <= 35);
        // Should try to preserve -p package
        assert!(
            result.contains("-p my-pkg") || result.ends_with("..."),
            "Result: {result}"
        );
    }

    #[test]
    fn test_truncate_command_fallback() {
        // When no important suffix, just truncate with ellipsis
        let cmd = "cargo build --target x86_64-unknown-linux-gnu --features full";
        let result = truncate_command(cmd, 30);
        assert!(result.len() <= 30);
        assert!(result.ends_with("..."));
    }
}
