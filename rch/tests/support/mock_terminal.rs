//! Mock terminal for testing rich UI components.
//!
//! Provides a simulated terminal environment for deterministic UI testing.

use std::io::{Cursor, Write};
use unicode_width::UnicodeWidthStr;

/// Mock terminal for testing rich UI components.
///
/// Captures output and simulates terminal properties without
/// actually writing to a real terminal.
pub struct MockTerminal {
    /// Terminal width in columns.
    pub width: usize,
    /// Terminal height in rows.
    pub height: usize,
    /// Output buffer.
    pub buffer: Cursor<Vec<u8>>,
    /// Whether color output is supported.
    pub supports_color: bool,
    /// Whether Unicode characters are supported.
    pub supports_unicode: bool,
    /// Cursor visibility state.
    #[allow(dead_code)]
    pub cursor_visible: bool,
    /// Current cursor X position.
    #[allow(dead_code)]
    pub cursor_x: usize,
    /// Current cursor Y position.
    #[allow(dead_code)]
    pub cursor_y: usize,
}

impl MockTerminal {
    /// Create a new mock terminal with the specified dimensions.
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            buffer: Cursor::new(Vec::new()),
            supports_color: true,
            supports_unicode: true,
            cursor_visible: true,
            cursor_x: 0,
            cursor_y: 0,
        }
    }

    /// Configure the terminal to not support color output.
    #[must_use]
    pub fn with_no_color(mut self) -> Self {
        self.supports_color = false;
        self
    }

    /// Configure the terminal to use ASCII only (no Unicode).
    #[must_use]
    pub fn with_ascii_only(mut self) -> Self {
        self.supports_unicode = false;
        self
    }

    /// Get all output as a string.
    pub fn output(&self) -> String {
        String::from_utf8_lossy(self.buffer.get_ref()).to_string()
    }

    /// Get output with ANSI escape codes stripped.
    pub fn plain_output(&self) -> String {
        strip_ansi_codes(&self.output())
    }

    /// Check if output contains ANSI escape codes.
    pub fn has_ansi_codes(&self) -> bool {
        self.output().contains("\x1b[")
    }

    /// Get the number of output lines.
    pub fn line_count(&self) -> usize {
        self.output().lines().count()
    }

    /// Get the maximum line width (visual width, not byte count).
    pub fn max_line_width(&self) -> usize {
        self.plain_output()
            .lines()
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0)
    }

    /// Write content to the mock terminal buffer.
    pub fn write(&mut self, content: &str) -> std::io::Result<()> {
        self.buffer.write_all(content.as_bytes())
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.buffer = Cursor::new(Vec::new());
    }
}

impl Default for MockTerminal {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

/// Strip ANSI escape codes from a string.
pub fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut plain_start = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\x1b' {
            result.push_str(&s[plain_start..i]);
            i += 1;

            while i < bytes.len() {
                if bytes[i].is_ascii_alphabetic() {
                    i += 1;
                    break;
                }
                i += 1;
            }

            plain_start = i;
            continue;
        }

        i += 1;
    }

    result.push_str(&s[plain_start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_terminal_creation() {
        let term = MockTerminal::new(120, 40);
        assert_eq!(term.width, 120);
        assert_eq!(term.height, 40);
        assert!(term.supports_color);
        assert!(term.supports_unicode);
    }

    #[test]
    fn test_mock_terminal_default() {
        let term = MockTerminal::default();
        assert_eq!(term.width, 80);
        assert_eq!(term.height, 24);
    }

    #[test]
    fn test_mock_terminal_no_color() {
        let term = MockTerminal::new(80, 24).with_no_color();
        assert!(!term.supports_color);
    }

    #[test]
    fn test_mock_terminal_ascii_only() {
        let term = MockTerminal::new(80, 24).with_ascii_only();
        assert!(!term.supports_unicode);
    }

    #[test]
    fn test_mock_terminal_write_and_read() {
        let mut term = MockTerminal::new(80, 24);
        term.write("Hello, world!").unwrap();
        assert_eq!(term.output(), "Hello, world!");
    }

    #[test]
    fn test_mock_terminal_clear() {
        let mut term = MockTerminal::new(80, 24);
        term.write("content").unwrap();
        term.clear();
        assert!(term.output().is_empty());
    }

    #[test]
    fn test_strip_ansi_codes() {
        let with_ansi = "\x1b[31mRed\x1b[0m Text";
        let plain = strip_ansi_codes(with_ansi);
        assert_eq!(plain, "Red Text");
    }

    #[test]
    fn test_has_ansi_codes() {
        let mut term = MockTerminal::new(80, 24);
        term.write("plain text").unwrap();
        assert!(!term.has_ansi_codes());

        term.clear();
        term.write("\x1b[32mgreen\x1b[0m").unwrap();
        assert!(term.has_ansi_codes());
    }

    #[test]
    fn test_line_count() {
        let mut term = MockTerminal::new(80, 24);
        term.write("line1\nline2\nline3").unwrap();
        assert_eq!(term.line_count(), 3);
    }

    #[test]
    fn test_max_line_width() {
        let mut term = MockTerminal::new(80, 24);
        term.write("short\nthis is a longer line\nx").unwrap();
        assert_eq!(term.max_line_width(), "this is a longer line".len());
    }

    #[test]
    fn test_max_line_width_with_unicode() {
        let mut term = MockTerminal::new(80, 24);
        // CJK characters are 2-wide
        term.write("日本語").unwrap();
        assert_eq!(term.max_line_width(), 6);
    }
}
