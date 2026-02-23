//! TUI test harness utilities.
//!
//! Provides test rendering utilities and assertion helpers
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

use ftui::Frame;
use ftui_core::geometry::Rect;
use ftui_render::buffer::Buffer;
use ftui_render::cell::Cell;
use ftui_render::grapheme_pool::GraphemePool;
use tracing::{debug, info};

/// Create a test buffer with the given dimensions and a fresh GraphemePool.
///
/// Returns a (Buffer, GraphemePool) pair for use in tests that need
/// direct buffer manipulation without rendering.
///
/// # Arguments
///
/// * `width` - Buffer width in columns
/// * `height` - Buffer height in rows
pub fn create_test_buffer(width: u16, height: u16) -> (Buffer, GraphemePool) {
    debug!("TEST HARNESS: creating test buffer {}x{}", width, height);
    (Buffer::new(width, height), GraphemePool::new())
}

/// Convert an ftui buffer to a string representation.
///
/// Iterates through each cell of the buffer, extracting the character content
/// and concatenating with newlines between rows. Handles both direct chars
/// and grapheme pool references for multi-codepoint clusters.
///
/// # Arguments
///
/// * `buffer` - The ftui buffer to convert
/// * `pool` - The grapheme pool for resolving grapheme IDs
///
/// # Returns
///
/// A string representation of the buffer contents, with newlines
/// between each row.
pub fn buffer_to_string(buffer: &Buffer, pool: &GraphemePool) -> String {
    let mut out = String::new();
    let width = buffer.width();
    let height = buffer.height();
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = buffer.get(x, y) {
                if cell.content.is_continuation() {
                    continue;
                }
                if cell.content.is_empty() {
                    out.push(' ');
                } else if let Some(ch) = cell.content.as_char() {
                    out.push(ch);
                } else if let Some(id) = cell.content.grapheme_id() {
                    if let Some(s) = pool.get(id) {
                        out.push_str(s);
                    } else {
                        out.push(' ');
                    }
                } else {
                    out.push(' ');
                }
            } else {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out
}

/// Write a string into a buffer at the given position, one char per cell.
fn set_string_in_buffer(buffer: &mut Buffer, x: u16, y: u16, s: &str) {
    for (i, ch) in s.chars().enumerate() {
        buffer.set(x + i as u16, y, Cell::from_char(ch));
    }
}

/// Render a TUI component to a string for testing.
///
/// Creates a test frame, invokes the draw function, and returns
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
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    draw(&mut frame);
    buffer_to_string(&frame.buffer, &pool)
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
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(area.width, area.height, &mut pool);
    // Normalize to origin since the frame buffer starts at (0, 0)
    let normalized = Rect::new(0, 0, area.width, area.height);
    draw(&mut frame, normalized);
    buffer_to_string(&frame.buffer, &pool)
}

/// Assert that rendered content contains an expected substring.
///
/// Provides detailed logging on assertion failure, showing what was
/// expected and what the actual content was.
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
    render_to_string(width, height, |f| super::widgets::render(f, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ftui_widgets::Widget;
    use ftui_widgets::block::Block;
    use ftui_widgets::borders::Borders;
    use tracing::info;

    #[test]
    fn test_create_test_buffer_default_size() {
        init_test_logging();
        info!("TEST START: test_create_test_buffer_default_size");
        let (buffer, _pool) = create_test_buffer(80, 24);
        assert_eq!(buffer.width(), 80);
        assert_eq!(buffer.height(), 24);
        info!("TEST PASS: test_create_test_buffer_default_size");
    }

    #[test]
    fn test_create_test_buffer_custom_size() {
        init_test_logging();
        info!("TEST START: test_create_test_buffer_custom_size");
        let (buffer, _pool) = create_test_buffer(120, 40);
        assert_eq!(buffer.width(), 120);
        assert_eq!(buffer.height(), 40);
        info!("TEST PASS: test_create_test_buffer_custom_size");
    }

    #[test]
    fn test_create_test_buffer_minimum_size() {
        init_test_logging();
        info!("TEST START: test_create_test_buffer_minimum_size");
        let (buffer, _pool) = create_test_buffer(1, 1);
        assert_eq!(buffer.width(), 1);
        assert_eq!(buffer.height(), 1);
        info!("TEST PASS: test_create_test_buffer_minimum_size");
    }

    #[test]
    fn test_buffer_to_string_empty() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_empty");
        let (buffer, pool) = create_test_buffer(5, 2);
        let result = buffer_to_string(&buffer, &pool);
        info!("VERIFY: buffer lines count = {}", result.lines().count());
        assert_eq!(result.lines().count(), 2);
        assert!(result.lines().all(|l| l.len() == 5));
        info!("TEST PASS: test_buffer_to_string_empty");
    }

    #[test]
    fn test_buffer_to_string_with_content() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_with_content");
        let (mut buffer, pool) = create_test_buffer(10, 1);
        set_string_in_buffer(&mut buffer, 0, 0, "Hello");
        let result = buffer_to_string(&buffer, &pool);
        info!("VERIFY: buffer contains Hello: {}", result.trim());
        assert!(result.contains("Hello"));
        info!("TEST PASS: test_buffer_to_string_with_content");
    }

    #[test]
    fn test_buffer_to_string_multiline() {
        init_test_logging();
        info!("TEST START: test_buffer_to_string_multiline");
        let (mut buffer, pool) = create_test_buffer(10, 3);
        set_string_in_buffer(&mut buffer, 0, 0, "Line 1");
        set_string_in_buffer(&mut buffer, 0, 1, "Line 2");
        set_string_in_buffer(&mut buffer, 0, 2, "Line 3");
        let result = buffer_to_string(&buffer, &pool);
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
            let block = Block::new()
                .title("Test")
                .borders(Borders::ALL);
            block.render(f.bounds(), f);
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
                let block = Block::new()
                    .title("Size Test")
                    .borders(Borders::ALL);
                block.render(f.bounds(), f);
            });
            info!(
                "VERIFY: render {}x{} produces {} lines",
                w,
                h,
                content.lines().count()
            );
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
            let block = Block::new()
                .title("Area")
                .borders(Borders::ALL);
            block.render(rect, f);
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
