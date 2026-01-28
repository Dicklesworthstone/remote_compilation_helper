//! TUI test harness utilities.
//!
//! Provides test terminal creation, rendering utilities, and assertion helpers
//! for testing TUI components without a real terminal.
//!
//! # Example
//!
//! ```ignore
//! use crate::tui::test_harness::{render_to_string, assert_rendered_contains};
//!
//! let content = render_to_string(80, 24, |f| {
//!     widgets::render(f, &state)
//! });
//! assert_rendered_contains(&content, "RCH Dashboard");
//! ```

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::*;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tracing::{debug, info};

/// Create a test terminal with the given dimensions.
///
/// Returns a terminal backed by a `TestBackend` that can be used
/// for rendering TUI components in tests.
///
/// # Arguments
///
/// * `width` - Terminal width in columns
/// * `height` - Terminal height in rows
///
/// # Example
///
/// ```ignore
/// let mut terminal = create_test_terminal(80, 24);
/// terminal.draw(|f| widgets::render(f, &state)).unwrap();
/// ```
pub fn create_test_terminal(width: u16, height: u16) -> Terminal<TestBackend> {
    debug!(
        "TEST HARNESS: creating test terminal {}x{}",
        width, height
    );
    let backend = TestBackend::new(width, height);
    Terminal::new(backend).expect("failed to create test terminal")
}

/// Convert a ratatui buffer to a string representation.
///
/// Iterates through each cell of the buffer, extracting the symbol
/// and concatenating with newlines between rows. This is useful for
/// asserting on rendered content.
///
/// # Arguments
///
/// * `buffer` - The ratatui buffer to convert
///
/// # Returns
///
/// A string representation of the buffer contents, with newlines
/// between each row.
pub fn buffer_to_string(buffer: &Buffer) -> String {
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

/// Render a TUI component to a string for testing.
///
/// Creates a test terminal, invokes the draw function, and returns
/// the rendered content as a string.
///
/// # Arguments
///
/// * `width` - Terminal width in columns
/// * `height` - Terminal height in rows
/// * `draw` - Closure that receives a Frame and renders content
///
/// # Example
///
/// ```ignore
/// let content = render_to_string(80, 24, |f| {
///     widgets::render(f, &state)
/// });
/// assert!(content.contains("Workers"));
/// ```
pub fn render_to_string<F>(width: u16, height: u16, mut draw: F) -> String
where
    F: FnMut(&mut Frame),
{
    debug!("TEST HARNESS: render_to_string {}x{}", width, height);
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f)).unwrap();
    buffer_to_string(terminal.backend().buffer())
}

/// Render a TUI component at a specific rectangular region.
///
/// Similar to `render_to_string` but allows specifying the exact
/// area to render into, useful for testing individual widgets.
///
/// # Arguments
///
/// * `area` - The rectangular area to render into
/// * `draw` - Closure that receives a Frame and the area to render
///
/// # Example
///
/// ```ignore
/// let content = render_to_area(Rect::new(0, 0, 60, 10), |f, area| {
///     render_workers_panel(f, area, &state, &colors)
/// });
/// ```
pub fn render_to_area<F>(area: Rect, mut draw: F) -> String
where
    F: FnMut(&mut Frame, Rect),
{
    debug!(
        "TEST HARNESS: render_to_area x={} y={} w={} h={}",
        area.x, area.y, area.width, area.height
    );
    let backend = TestBackend::new(area.width, area.height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, area)).unwrap();
    buffer_to_string(terminal.backend().buffer())
}

/// Assert that rendered content contains an expected substring.
///
/// Provides detailed logging on assertion failure, showing what was
/// expected and what the actual content was.
///
/// # Arguments
///
/// * `content` - The rendered content string
/// * `expected` - The substring that should be present
///
/// # Panics
///
/// Panics if the expected substring is not found in the content.
pub fn assert_rendered_contains(content: &str, expected: &str) {
    if !content.contains(expected) {
        info!(
            "ASSERT FAILED: expected '{}' not found in rendered content",
            expected
        );
        info!("CONTENT:\n{}", content);
        panic!(
            "Expected rendered content to contain '{}' but it was not found",
            expected
        );
    }
    debug!("ASSERT PASS: found '{}' in rendered content", expected);
}

/// Assert that rendered content does NOT contain a substring.
///
/// Useful for verifying that certain elements are hidden or removed.
///
/// # Arguments
///
/// * `content` - The rendered content string
/// * `unexpected` - The substring that should NOT be present
///
/// # Panics
///
/// Panics if the unexpected substring is found in the content.
pub fn assert_rendered_not_contains(content: &str, unexpected: &str) {
    if content.contains(unexpected) {
        info!(
            "ASSERT FAILED: unexpected '{}' found in rendered content",
            unexpected
        );
        info!("CONTENT:\n{}", content);
        panic!(
            "Expected rendered content to NOT contain '{}' but it was found",
            unexpected
        );
    }
    debug!(
        "ASSERT PASS: '{}' correctly absent from rendered content",
        unexpected
    );
}

/// Assert that rendered content matches multiple expectations.
///
/// Convenience function for checking multiple substrings at once.
///
/// # Arguments
///
/// * `content` - The rendered content string
/// * `expected` - Slice of substrings that should all be present
///
/// # Panics
///
/// Panics if any expected substring is not found.
pub fn assert_rendered_contains_all(content: &str, expected: &[&str]) {
    for exp in expected {
        assert_rendered_contains(content, exp);
    }
}

/// Get the terminal size from environment or use defaults.
///
/// Reads COLUMNS and LINES environment variables, with fallback
/// to 80x24. Enforces minimum dimensions for rendering.
///
/// # Returns
///
/// Tuple of (width, height) with minimum values of (40, 12).
pub fn get_test_terminal_size() -> (u16, u16) {
    let width = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(80);
    let height = std::env::var("LINES")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(24);
    (width.max(40), height.max(12))
}

/// Initialize test logging for TUI tests.
///
/// Configures tracing subscriber with test writer for capturing
/// log output in test assertions. Safe to call multiple times.
pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

/// Snapshot a TUI state rendering for comparison or visual inspection.
///
/// Creates a snapshot of the rendered state at the specified dimensions.
/// Useful for debugging test failures by examining the actual output.
///
/// # Arguments
///
/// * `state` - The TuiState to render
/// * `width` - Terminal width
/// * `height` - Terminal height
///
/// # Returns
///
/// String representation of the rendered state.
pub fn snapshot_state(state: &super::TuiState, width: u16, height: u16) -> String {
    render_to_string(width, height, |f| {
        super::widgets::render(f, state)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    #[test]
    fn test_create_test_terminal_default_size() {
        init_test_logging();
        info!("TEST START: test_create_test_terminal_default_size");
        let terminal = create_test_terminal(80, 24);
        let size = terminal.size().unwrap();
        assert_eq!(size.width, 80);
        assert_eq!(size.height, 24);
        info!("TEST PASS: test_create_test_terminal_default_size");
    }

    #[test]
    fn test_create_test_terminal_custom_size() {
        init_test_logging();
        info!("TEST START: test_create_test_terminal_custom_size");
        let terminal = create_test_terminal(120, 40);
        let size = terminal.size().unwrap();
        assert_eq!(size.width, 120);
        assert_eq!(size.height, 40);
        info!("TEST PASS: test_create_test_terminal_custom_size");
    }

    #[test]
    fn test_create_test_terminal_minimum_size() {
        init_test_logging();
        info!("TEST START: test_create_test_terminal_minimum_size");
        let terminal = create_test_terminal(1, 1);
        let size = terminal.size().unwrap();
        assert_eq!(size.width, 1);
        assert_eq!(size.height, 1);
        info!("TEST PASS: test_create_test_terminal_minimum_size");
    }

    #[test]
    fn test_buffer_to_string_empty() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_empty");
        let rect = Rect::new(0, 0, 5, 2);
        let buffer = Buffer::empty(rect);
        let result = buffer_to_string(&buffer);
        info!("VERIFY: buffer lines count = {}", result.lines().count());
        assert_eq!(result.lines().count(), 2);
        assert!(result.lines().all(|l| l.len() == 5));
        info!("TEST PASS: test_buffer_to_string_empty");
    }

    #[test]
    fn test_buffer_to_string_with_content() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_with_content");
        let rect = Rect::new(0, 0, 10, 1);
        let mut buffer = Buffer::empty(rect);
        buffer.set_string(0, 0, "Hello", Style::default());
        let result = buffer_to_string(&buffer);
        info!("VERIFY: buffer contains Hello: {}", result.trim());
        assert!(result.contains("Hello"));
        info!("TEST PASS: test_buffer_to_string_with_content");
    }

    #[test]
    fn test_buffer_to_string_multiline() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_multiline");
        let rect = Rect::new(0, 0, 10, 3);
        let mut buffer = Buffer::empty(rect);
        buffer.set_string(0, 0, "Line 1", Style::default());
        buffer.set_string(0, 1, "Line 2", Style::default());
        buffer.set_string(0, 2, "Line 3", Style::default());
        let result = buffer_to_string(&buffer);
        info!("VERIFY: buffer has 3 lines");
        assert!(result.contains("Line 1"));
        assert!(result.contains("Line 2"));
        assert!(result.contains("Line 3"));
        assert_eq!(result.lines().count(), 3);
        info!("TEST PASS: test_buffer_to_string_multiline");
    }

    #[test]
    fn test_render_to_string_basic() {
        init_test_logging();
        info!("TEST START: test_render_to_string_basic");
        let content = render_to_string(20, 5, |f| {
            let block = ratatui::widgets::Block::default()
                .title("Test")
                .borders(ratatui::widgets::Borders::ALL);
            f.render_widget(block, f.area());
        });
        info!("VERIFY: rendered content contains title");
        assert!(content.contains("Test"));
        info!("TEST PASS: test_render_to_string_basic");
    }

    #[test]
    fn test_render_to_string_at_various_sizes() {
        init_test_logging();
        info!("TEST START: test_render_to_string_at_various_sizes");
        for (w, h) in [(40, 12), (80, 24), (120, 40)] {
            let content = render_to_string(w, h, |f| {
                let block = ratatui::widgets::Block::default()
                    .title("Size Test")
                    .borders(ratatui::widgets::Borders::ALL);
                f.render_widget(block, f.area());
            });
            info!("VERIFY: render {}x{} produces {} lines", w, h, content.lines().count());
            assert!(content.lines().count() >= h as usize);
        }
        info!("TEST PASS: test_render_to_string_at_various_sizes");
    }

    #[test]
    fn test_render_to_area() {
        init_test_logging();
        info!("TEST START: test_render_to_area");
        let area = Rect::new(0, 0, 30, 5);
        let content = render_to_area(area, |f, rect| {
            let block = ratatui::widgets::Block::default()
                .title("Area")
                .borders(ratatui::widgets::Borders::ALL);
            f.render_widget(block, rect);
        });
        info!("VERIFY: rendered area contains title");
        assert!(content.contains("Area"));
        info!("TEST PASS: test_render_to_area");
    }

    #[test]
    fn test_assert_rendered_contains_pass() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_contains_pass");
        let content = "Hello World";
        assert_rendered_contains(content, "Hello");
        assert_rendered_contains(content, "World");
        assert_rendered_contains(content, "llo Wo");
        info!("TEST PASS: test_assert_rendered_contains_pass");
    }

    #[test]
    #[should_panic(expected = "Expected rendered content to contain")]
    fn test_assert_rendered_contains_fail() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_contains_fail");
        let content = "Hello World";
        assert_rendered_contains(content, "Goodbye");
    }

    #[test]
    fn test_assert_rendered_not_contains_pass() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_not_contains_pass");
        let content = "Hello World";
        assert_rendered_not_contains(content, "Goodbye");
        assert_rendered_not_contains(content, "xyz");
        info!("TEST PASS: test_assert_rendered_not_contains_pass");
    }

    #[test]
    #[should_panic(expected = "Expected rendered content to NOT contain")]
    fn test_assert_rendered_not_contains_fail() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_not_contains_fail");
        let content = "Hello World";
        assert_rendered_not_contains(content, "Hello");
    }

    #[test]
    fn test_assert_rendered_contains_all_pass() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_contains_all_pass");
        let content = "Hello World Foo Bar";
        assert_rendered_contains_all(content, &["Hello", "World", "Foo", "Bar"]);
        info!("TEST PASS: test_assert_rendered_contains_all_pass");
    }

    #[test]
    #[should_panic(expected = "Expected rendered content to contain")]
    fn test_assert_rendered_contains_all_fail() {
        init_test_logging();
        info!("TEST START: test_assert_rendered_contains_all_fail");
        let content = "Hello World";
        assert_rendered_contains_all(content, &["Hello", "Missing"]);
    }

    #[test]
    fn test_get_test_terminal_size_defaults() {
        init_test_logging();
        info!("TEST START: test_get_test_terminal_size_defaults");
        let (w, h) = get_test_terminal_size();
        info!("VERIFY: terminal size w={} h={}", w, h);
        assert!(w >= 40);
        assert!(h >= 12);
        info!("TEST PASS: test_get_test_terminal_size_defaults");
    }

    #[test]
    fn test_init_test_logging_idempotent() {
        // Should be safe to call multiple times
        init_test_logging();
        init_test_logging();
        init_test_logging();
        info!("TEST PASS: test_init_test_logging_idempotent");
    }
}
