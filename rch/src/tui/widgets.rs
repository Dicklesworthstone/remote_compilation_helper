//! TUI widgets for dashboard components.
//!
//! Custom widgets for workers, builds, and status display.

use crate::tui::state::{BuildStatus, CircuitState, Panel, TuiState, WorkerStatus};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

/// Get color scheme based on high contrast mode.
fn get_colors(high_contrast: bool) -> ColorScheme {
    if high_contrast {
        ColorScheme {
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
        }
    } else {
        ColorScheme {
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
        }
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
    let colors = get_colors(state.high_contrast);

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
            let circuit_icon = match w.circuit {
                CircuitState::Closed => "",
                CircuitState::HalfOpen => " ⚡",
                CircuitState::Open => " 🔴",
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
            let status_icon = match b.status {
                BuildStatus::Pending => "⏳",
                BuildStatus::Syncing => "📤",
                BuildStatus::Compiling => "🔨",
                BuildStatus::Downloading => "📥",
                BuildStatus::Completed => "✅",
                BuildStatus::Failed => "❌",
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

            // Truncate command for display
            let cmd = if b.command.len() > 40 {
                format!("{}...", &b.command[..37])
            } else {
                b.command.clone()
            };

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

            // Truncate command
            let cmd = if b.command.len() > 30 {
                format!("{}...", &b.command[..27])
            } else {
                b.command.clone()
            };

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
    // Center the help box
    let width = 60.min(area.width.saturating_sub(4));
    let height = 18.min(area.height.saturating_sub(4));
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
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  r           Refresh data from daemon"),
        Line::from("  /           Filter build history"),
        Line::from("  y           Copy selected item"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("  q, Esc      Quit / Close overlay"),
        Line::from("  ?           Toggle this help"),
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
    let feedback_area = Rect::new(area.width.saturating_sub(20), 1, 18, 1);

    let feedback = Paragraph::new(Span::styled(
        "Copied to clipboard!",
        Style::default().fg(colors.success),
    ));

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
