//! Styled box rendering with borders, padding, and margins.
//!
//! Inspired by Charm's Lip Gloss, this module provides a consistent API for
//! rendering styled content blocks - the foundation for premium CLI output
//! like headers, status displays, and confirmation dialogs.
//!
//! # Usage
//!
//! ```rust,ignore
//! use rch::ui::styled::{BoxStyle, BorderStyle, Padding, Align};
//!
//! let style = BoxStyle::new()
//!     .border(BorderStyle::Rounded)
//!     .border_color(Color::Cyan)
//!     .padding(Padding::horizontal(1))
//!     .width(50)
//!     .align(Align::Center);
//!
//! let output = style.render("Hello, World!", ctx);
//! ```

use colored::{Color, Colorize};
use std::borrow::Cow;
use unicode_width::UnicodeWidthStr;

/// Border drawing characters for a box.
#[derive(Debug, Clone, Copy)]
pub struct BorderChars {
    pub top_left: char,
    pub top: char,
    pub top_right: char,
    pub left: char,
    pub right: char,
    pub bottom_left: char,
    pub bottom: char,
    pub bottom_right: char,
}

impl BorderChars {
    /// Empty border (no visible characters, just spacing).
    pub const EMPTY: Self = Self {
        top_left: ' ',
        top: ' ',
        top_right: ' ',
        left: ' ',
        right: ' ',
        bottom_left: ' ',
        bottom: ' ',
        bottom_right: ' ',
    };
}

/// Border style presets for boxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BorderStyle {
    /// No border.
    #[default]
    None,
    /// Standard box drawing characters: ┌─┐│└─┘
    Normal,
    /// Rounded corners: ╭─╮│╰─╯
    Rounded,
    /// Double lines: ╔═╗║╚═╝
    Double,
    /// Thick/heavy lines: ┏━┓┃┗━┛
    Thick,
    /// Hidden border (padding space, no visible border).
    Hidden,
}

impl BorderStyle {
    /// Get Unicode border characters for this style.
    pub fn chars(&self) -> BorderChars {
        match self {
            Self::None => BorderChars::EMPTY,
            Self::Normal => BorderChars {
                top_left: '┌',
                top: '─',
                top_right: '┐',
                left: '│',
                right: '│',
                bottom_left: '└',
                bottom: '─',
                bottom_right: '┘',
            },
            Self::Rounded => BorderChars {
                top_left: '╭',
                top: '─',
                top_right: '╮',
                left: '│',
                right: '│',
                bottom_left: '╰',
                bottom: '─',
                bottom_right: '╯',
            },
            Self::Double => BorderChars {
                top_left: '╔',
                top: '═',
                top_right: '╗',
                left: '║',
                right: '║',
                bottom_left: '╚',
                bottom: '═',
                bottom_right: '╝',
            },
            Self::Thick => BorderChars {
                top_left: '┏',
                top: '━',
                top_right: '┓',
                left: '┃',
                right: '┃',
                bottom_left: '┗',
                bottom: '━',
                bottom_right: '┛',
            },
            Self::Hidden => BorderChars {
                top_left: ' ',
                top: ' ',
                top_right: ' ',
                left: ' ',
                right: ' ',
                bottom_left: ' ',
                bottom: ' ',
                bottom_right: ' ',
            },
        }
    }

    /// Get ASCII fallback border characters for non-Unicode terminals.
    pub fn ascii_chars(&self) -> BorderChars {
        match self {
            Self::None => BorderChars::EMPTY,
            Self::Hidden => BorderChars::EMPTY,
            _ => BorderChars {
                top_left: '+',
                top: '-',
                top_right: '+',
                left: '|',
                right: '|',
                bottom_left: '+',
                bottom: '-',
                bottom_right: '+',
            },
        }
    }

    /// Check if this style has a visible border.
    pub fn has_border(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Check if this style takes up space (border or hidden padding).
    pub fn takes_space(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Padding/margin spacing for all four sides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spacing {
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
    pub left: u16,
}

impl Spacing {
    /// Create spacing with the same value on all sides.
    pub fn all(v: u16) -> Self {
        Self {
            top: v,
            right: v,
            bottom: v,
            left: v,
        }
    }

    /// Create spacing with horizontal (left/right) values only.
    pub fn horizontal(h: u16) -> Self {
        Self {
            top: 0,
            right: h,
            bottom: 0,
            left: h,
        }
    }

    /// Create spacing with vertical (top/bottom) values only.
    pub fn vertical(v: u16) -> Self {
        Self {
            top: v,
            right: 0,
            bottom: v,
            left: 0,
        }
    }

    /// Create spacing with individual values for each side.
    pub fn new(top: u16, right: u16, bottom: u16, left: u16) -> Self {
        Self {
            top,
            right,
            bottom,
            left,
        }
    }

    /// Total horizontal spacing (left + right).
    pub fn horizontal_total(&self) -> u16 {
        self.left + self.right
    }

    /// Total vertical spacing (top + bottom).
    pub fn vertical_total(&self) -> u16 {
        self.top + self.bottom
    }
}

/// Type alias for padding.
pub type Padding = Spacing;

/// Type alias for margin.
pub type Margin = Spacing;

/// Text alignment within a box.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Align {
    /// Left-align text (default).
    #[default]
    Left,
    /// Center text horizontally.
    Center,
    /// Right-align text.
    Right,
}

/// Style configuration for rendering boxes.
#[derive(Debug, Clone, Default)]
pub struct BoxStyle {
    /// Border style.
    pub border: BorderStyle,
    /// Border color.
    pub border_color: Option<Color>,
    /// Inner padding.
    pub padding: Padding,
    /// Outer margin.
    pub margin: Margin,
    /// Fixed width (0 = auto).
    pub width: u16,
    /// Maximum width (0 = unlimited).
    pub max_width: u16,
    /// Minimum width (0 = none).
    pub min_width: u16,
    /// Horizontal text alignment.
    pub align: Align,
    /// Foreground color.
    pub foreground: Option<Color>,
    /// Background color.
    pub background: Option<Color>,
    /// Bold text.
    pub bold: bool,
    /// Italic text.
    pub italic: bool,
    /// Dimmed/faint text.
    pub dim: bool,
}

impl BoxStyle {
    /// Create a new default box style.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the border style.
    pub fn border(mut self, style: BorderStyle) -> Self {
        self.border = style;
        self
    }

    /// Set the border color.
    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = Some(color);
        self
    }

    /// Set the inner padding.
    pub fn padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// Set the outer margin.
    pub fn margin(mut self, margin: Margin) -> Self {
        self.margin = margin;
        self
    }

    /// Set the fixed width.
    pub fn width(mut self, width: u16) -> Self {
        self.width = width;
        self
    }

    /// Set the maximum width.
    pub fn max_width(mut self, max_width: u16) -> Self {
        self.max_width = max_width;
        self
    }

    /// Set the minimum width.
    pub fn min_width(mut self, min_width: u16) -> Self {
        self.min_width = min_width;
        self
    }

    /// Set the horizontal text alignment.
    pub fn align(mut self, align: Align) -> Self {
        self.align = align;
        self
    }

    /// Set the foreground color.
    pub fn foreground(mut self, color: Color) -> Self {
        self.foreground = Some(color);
        self
    }

    /// Set the background color.
    pub fn background(mut self, color: Color) -> Self {
        self.background = Some(color);
        self
    }

    /// Enable bold text.
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Enable italic text.
    pub fn italic(mut self) -> Self {
        self.italic = true;
        self
    }

    /// Enable dimmed/faint text.
    pub fn dim(mut self) -> Self {
        self.dim = true;
        self
    }

    /// Render content with this style applied.
    ///
    /// # Arguments
    /// * `content` - The text to render inside the box
    /// * `colors_enabled` - Whether ANSI colors should be used
    /// * `unicode_enabled` - Whether Unicode characters should be used
    pub fn render(&self, content: &str, colors_enabled: bool, unicode_enabled: bool) -> String {
        let mut result = String::new();

        // Split content into lines
        let content_lines: Vec<&str> = content.lines().collect();

        // Calculate content width (widest line)
        let content_width = content_lines
            .iter()
            .map(|line| UnicodeWidthStr::width(*line))
            .max()
            .unwrap_or(0) as u16;

        // Determine the box inner width
        let inner_width = self.calculate_inner_width(content_width);

        // Get border chars
        let border_chars = if unicode_enabled {
            self.border.chars()
        } else {
            self.border.ascii_chars()
        };

        // Calculate total box width (inner + border + padding)
        let has_border = self.border.takes_space();
        let border_width = if has_border { 2 } else { 0 };
        let total_width = inner_width + self.padding.horizontal_total() + border_width;

        // Add top margin
        for _ in 0..self.margin.top {
            result.push('\n');
        }

        // Render top border
        if has_border {
            let margin_indent = " ".repeat(self.margin.left as usize);
            let top_line = format!(
                "{}{}{}{}",
                margin_indent,
                border_chars.top_left,
                border_chars
                    .top
                    .to_string()
                    .repeat((total_width - 2) as usize),
                border_chars.top_right
            );
            if colors_enabled {
                if let Some(color) = self.border_color {
                    result.push_str(&top_line.color(color).to_string());
                } else {
                    result.push_str(&top_line);
                }
            } else {
                result.push_str(&top_line);
            }
            result.push('\n');
        }

        // Add top padding lines
        for _ in 0..self.padding.top {
            result.push_str(&self.render_padding_line(
                inner_width,
                &border_chars,
                has_border,
                colors_enabled,
            ));
            result.push('\n');
        }

        // Render content lines
        for line in &content_lines {
            let styled_line = self.render_content_line(
                line,
                inner_width,
                &border_chars,
                has_border,
                colors_enabled,
            );
            result.push_str(&styled_line);
            result.push('\n');
        }

        // Add bottom padding lines
        for _ in 0..self.padding.bottom {
            result.push_str(&self.render_padding_line(
                inner_width,
                &border_chars,
                has_border,
                colors_enabled,
            ));
            result.push('\n');
        }

        // Render bottom border
        if has_border {
            let margin_indent = " ".repeat(self.margin.left as usize);
            let bottom_line = format!(
                "{}{}{}{}",
                margin_indent,
                border_chars.bottom_left,
                border_chars
                    .bottom
                    .to_string()
                    .repeat((total_width - 2) as usize),
                border_chars.bottom_right
            );
            if colors_enabled {
                if let Some(color) = self.border_color {
                    result.push_str(&bottom_line.color(color).to_string());
                } else {
                    result.push_str(&bottom_line);
                }
            } else {
                result.push_str(&bottom_line);
            }
        }

        // Add bottom margin
        for _ in 0..self.margin.bottom {
            result.push('\n');
        }

        // Trim trailing newline if present
        if result.ends_with('\n') {
            result.pop();
        }

        result
    }

    /// Calculate the inner width for content.
    fn calculate_inner_width(&self, content_width: u16) -> u16 {
        let mut width = if self.width > 0 {
            self.width
        } else {
            content_width
        };

        // Apply min/max constraints
        if self.min_width > 0 && width < self.min_width {
            width = self.min_width;
        }
        if self.max_width > 0 && width > self.max_width {
            width = self.max_width;
        }

        width
    }

    /// Render a padding line (empty content row within the box).
    fn render_padding_line(
        &self,
        inner_width: u16,
        border_chars: &BorderChars,
        has_border: bool,
        colors_enabled: bool,
    ) -> String {
        let margin_indent = " ".repeat(self.margin.left as usize);
        let padding_left = " ".repeat(self.padding.left as usize);
        let padding_right = " ".repeat(self.padding.right as usize);
        let inner_space = " ".repeat(inner_width as usize);

        if has_border {
            let left_border = border_chars.left.to_string();
            let right_border = border_chars.right.to_string();

            if colors_enabled {
                if let Some(color) = self.border_color {
                    format!(
                        "{}{}{}{}{}{}",
                        margin_indent,
                        left_border.color(color),
                        padding_left,
                        inner_space,
                        padding_right,
                        right_border.color(color)
                    )
                } else {
                    format!(
                        "{}{}{}{}{}{}",
                        margin_indent,
                        left_border,
                        padding_left,
                        inner_space,
                        padding_right,
                        right_border
                    )
                }
            } else {
                format!(
                    "{}{}{}{}{}{}",
                    margin_indent,
                    left_border,
                    padding_left,
                    inner_space,
                    padding_right,
                    right_border
                )
            }
        } else {
            format!(
                "{}{}{}{}",
                margin_indent, padding_left, inner_space, padding_right
            )
        }
    }

    /// Render a content line within the box.
    fn render_content_line(
        &self,
        line: &str,
        inner_width: u16,
        border_chars: &BorderChars,
        has_border: bool,
        colors_enabled: bool,
    ) -> String {
        let margin_indent = " ".repeat(self.margin.left as usize);
        let padding_left = " ".repeat(self.padding.left as usize);
        let padding_right = " ".repeat(self.padding.right as usize);

        // Calculate padding for alignment
        let line_width = UnicodeWidthStr::width(line) as u16;
        let space_available = inner_width.saturating_sub(line_width);

        let (left_pad, right_pad) = match self.align {
            Align::Left => (0, space_available),
            Align::Right => (space_available, 0),
            Align::Center => {
                let left = space_available / 2;
                let right = space_available - left;
                (left, right)
            }
        };

        // Style the content text
        let styled_content: Cow<str> = if colors_enabled
            && (self.foreground.is_some()
                || self.background.is_some()
                || self.bold
                || self.italic
                || self.dim)
        {
            let mut styled = line.normal();
            if let Some(fg) = self.foreground {
                styled = styled.color(fg);
            }
            if let Some(bg) = self.background {
                styled = styled.on_color(bg);
            }
            if self.bold {
                styled = styled.bold();
            }
            if self.italic {
                styled = styled.italic();
            }
            if self.dim {
                styled = styled.dimmed();
            }
            Cow::Owned(styled.to_string())
        } else {
            Cow::Borrowed(line)
        };

        let inner_content = format!(
            "{}{}{}",
            " ".repeat(left_pad as usize),
            styled_content,
            " ".repeat(right_pad as usize)
        );

        if has_border {
            let left_border = border_chars.left.to_string();
            let right_border = border_chars.right.to_string();

            if colors_enabled {
                if let Some(color) = self.border_color {
                    format!(
                        "{}{}{}{}{}{}",
                        margin_indent,
                        left_border.color(color),
                        padding_left,
                        inner_content,
                        padding_right,
                        right_border.color(color)
                    )
                } else {
                    format!(
                        "{}{}{}{}{}{}",
                        margin_indent,
                        left_border,
                        padding_left,
                        inner_content,
                        padding_right,
                        right_border
                    )
                }
            } else {
                format!(
                    "{}{}{}{}{}{}",
                    margin_indent,
                    left_border,
                    padding_left,
                    inner_content,
                    padding_right,
                    right_border
                )
            }
        } else {
            format!(
                "{}{}{}{}",
                margin_indent, padding_left, inner_content, padding_right
            )
        }
    }
}

// ============================================================================
// Layout Utilities
// ============================================================================

/// Join multiple blocks horizontally with consistent height.
pub fn join_horizontal(items: &[&str], spacing: u16) -> String {
    if items.is_empty() {
        return String::new();
    }

    // Split each item into lines
    let item_lines: Vec<Vec<&str>> = items.iter().map(|s| s.lines().collect()).collect();

    // Find max height
    let max_height = item_lines
        .iter()
        .map(|lines| lines.len())
        .max()
        .unwrap_or(0);

    // Find width of each item
    let item_widths: Vec<usize> = item_lines
        .iter()
        .map(|lines| {
            lines
                .iter()
                .map(|line| UnicodeWidthStr::width(*line))
                .max()
                .unwrap_or(0)
        })
        .collect();

    // Build result line by line
    let mut result = Vec::new();
    let spacer = " ".repeat(spacing as usize);

    for row in 0..max_height {
        let mut line_parts = Vec::new();

        for (i, lines) in item_lines.iter().enumerate() {
            let width = item_widths[i];
            let content = lines.get(row).copied().unwrap_or("");
            let content_width = UnicodeWidthStr::width(content);
            let padding = width.saturating_sub(content_width);
            line_parts.push(format!("{}{}", content, " ".repeat(padding)));
        }

        result.push(line_parts.join(&spacer));
    }

    result.join("\n")
}

/// Join multiple blocks vertically.
pub fn join_vertical(items: &[&str]) -> String {
    items.join("\n")
}

/// Place content at a specific position within a canvas.
pub fn place(width: u16, height: u16, h_align: Align, v_align: Align, content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let content_height = lines.len() as u16;
    let content_width = lines
        .iter()
        .map(|line| UnicodeWidthStr::width(*line))
        .max()
        .unwrap_or(0) as u16;

    // Calculate vertical position
    let (top_pad, bottom_pad) = match v_align {
        Align::Left => (0, height.saturating_sub(content_height)), // Top
        Align::Center => {
            let pad = height.saturating_sub(content_height);
            let top = pad / 2;
            (top, pad - top)
        }
        Align::Right => (height.saturating_sub(content_height), 0), // Bottom
    };

    // Calculate horizontal padding
    let h_space = width.saturating_sub(content_width);
    let (left_pad, right_pad) = match h_align {
        Align::Left => (0, h_space),
        Align::Center => {
            let left = h_space / 2;
            (left, h_space - left)
        }
        Align::Right => (h_space, 0),
    };

    let mut result = Vec::new();

    // Add top padding
    for _ in 0..top_pad {
        result.push(" ".repeat(width as usize));
    }

    // Add content lines with horizontal padding
    for line in &lines {
        let line_width = UnicodeWidthStr::width(*line) as u16;
        let extra_right = (content_width - line_width) + right_pad;
        result.push(format!(
            "{}{}{}",
            " ".repeat(left_pad as usize),
            line,
            " ".repeat(extra_right as usize)
        ));
    }

    // Add bottom padding
    for _ in 0..bottom_pad {
        result.push(" ".repeat(width as usize));
    }

    result.join("\n")
}

// ============================================================================
// Preset Styles
// ============================================================================

/// Preset box styles for common use cases.
pub mod presets {
    use super::*;

    /// Info box with rounded corners and cyan border.
    pub fn info_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Rounded)
            .border_color(Color::Cyan)
            .padding(Padding::horizontal(1))
    }

    /// Warning box with rounded corners and yellow border.
    pub fn warning_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Rounded)
            .border_color(Color::Yellow)
            .foreground(Color::Yellow)
            .padding(Padding::horizontal(1))
    }

    /// Error box with rounded corners and red border.
    pub fn error_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Rounded)
            .border_color(Color::Red)
            .foreground(Color::Red)
            .padding(Padding::horizontal(1))
    }

    /// Success box with rounded corners and green border.
    pub fn success_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Rounded)
            .border_color(Color::Green)
            .foreground(Color::Green)
            .padding(Padding::horizontal(1))
    }

    /// Title box with double border and bold text.
    pub fn title_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Double)
            .padding(Padding::new(0, 2, 0, 2))
            .bold()
    }

    /// Dialog box for confirmations with thick border.
    pub fn dialog_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Thick)
            .padding(Padding::all(1))
            .align(Align::Center)
    }

    /// Status box with normal border for key-value displays.
    pub fn status_box() -> BoxStyle {
        BoxStyle::new()
            .border(BorderStyle::Normal)
            .padding(Padding::horizontal(1))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_border_style_chars() {
        let normal = BorderStyle::Normal.chars();
        assert_eq!(normal.top_left, '┌');
        assert_eq!(normal.top_right, '┐');

        let rounded = BorderStyle::Rounded.chars();
        assert_eq!(rounded.top_left, '╭');
        assert_eq!(rounded.bottom_right, '╯');

        let double = BorderStyle::Double.chars();
        assert_eq!(double.left, '║');
        assert_eq!(double.top, '═');
    }

    #[test]
    fn test_border_style_ascii_fallback() {
        let ascii = BorderStyle::Normal.ascii_chars();
        assert_eq!(ascii.top_left, '+');
        assert_eq!(ascii.top, '-');
        assert_eq!(ascii.left, '|');
    }

    #[test]
    fn test_spacing_all() {
        let spacing = Spacing::all(2);
        assert_eq!(spacing.top, 2);
        assert_eq!(spacing.right, 2);
        assert_eq!(spacing.bottom, 2);
        assert_eq!(spacing.left, 2);
    }

    #[test]
    fn test_spacing_horizontal() {
        let spacing = Spacing::horizontal(3);
        assert_eq!(spacing.top, 0);
        assert_eq!(spacing.right, 3);
        assert_eq!(spacing.bottom, 0);
        assert_eq!(spacing.left, 3);
        assert_eq!(spacing.horizontal_total(), 6);
    }

    #[test]
    fn test_spacing_vertical() {
        let spacing = Spacing::vertical(2);
        assert_eq!(spacing.top, 2);
        assert_eq!(spacing.right, 0);
        assert_eq!(spacing.bottom, 2);
        assert_eq!(spacing.left, 0);
        assert_eq!(spacing.vertical_total(), 4);
    }

    #[test]
    fn test_box_style_builder() {
        let style = BoxStyle::new()
            .border(BorderStyle::Rounded)
            .border_color(Color::Cyan)
            .padding(Padding::all(1))
            .width(40)
            .align(Align::Center)
            .bold();

        assert_eq!(style.border, BorderStyle::Rounded);
        assert_eq!(style.border_color, Some(Color::Cyan));
        assert_eq!(style.padding.top, 1);
        assert_eq!(style.width, 40);
        assert_eq!(style.align, Align::Center);
        assert!(style.bold);
    }

    #[test]
    fn test_render_simple_box_no_colors() {
        let style = BoxStyle::new().border(BorderStyle::Normal).width(10);

        let output = style.render("Hello", false, true);

        assert!(output.contains('┌'));
        assert!(output.contains('└'));
        assert!(output.contains('│'));
        assert!(output.contains("Hello"));
    }

    #[test]
    fn test_render_box_ascii_fallback() {
        let style = BoxStyle::new().border(BorderStyle::Rounded).width(10);

        let output = style.render("Hi", false, false);

        assert!(output.contains('+'));
        assert!(output.contains('-'));
        assert!(output.contains('|'));
        assert!(!output.contains('╭')); // No unicode
    }

    #[test]
    fn test_render_box_with_padding() {
        let style = BoxStyle::new()
            .border(BorderStyle::Normal)
            .padding(Padding::all(1))
            .width(10);

        let output = style.render("Hi", false, true);
        let lines: Vec<&str> = output.lines().collect();

        // Should have: top border, top padding, content, bottom padding, bottom border
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_render_multiline_content() {
        let style = BoxStyle::new().border(BorderStyle::Normal).width(20);

        let output = style.render("Line 1\nLine 2\nLine 3", false, true);
        let lines: Vec<&str> = output.lines().collect();

        // top border + 3 content lines + bottom border = 5
        assert_eq!(lines.len(), 5);
        assert!(output.contains("Line 1"));
        assert!(output.contains("Line 2"));
        assert!(output.contains("Line 3"));
    }

    #[test]
    fn test_alignment_left() {
        let style = BoxStyle::new()
            .border(BorderStyle::Normal)
            .align(Align::Left)
            .width(20);

        let output = style.render("Hi", false, true);

        // Content should be left-aligned (followed by spaces)
        assert!(output.contains("│Hi                  │"));
    }

    #[test]
    fn test_alignment_center() {
        let style = BoxStyle::new()
            .border(BorderStyle::Normal)
            .align(Align::Center)
            .width(20);

        let output = style.render("Hi", false, true);

        // Content should be centered
        assert!(output.contains("│         Hi         │"));
    }

    #[test]
    fn test_alignment_right() {
        let style = BoxStyle::new()
            .border(BorderStyle::Normal)
            .align(Align::Right)
            .width(20);

        let output = style.render("Hi", false, true);

        // Content should be right-aligned
        assert!(output.contains("│                  Hi│"));
    }

    #[test]
    fn test_no_border() {
        let style = BoxStyle::new().border(BorderStyle::None).width(10);

        let output = style.render("Hello", false, true);

        assert!(!output.contains('│'));
        assert!(!output.contains('┌'));
        assert!(output.contains("Hello"));
    }

    #[test]
    fn test_join_horizontal() {
        let box1 = "A\nB";
        let box2 = "1\n2";

        let joined = join_horizontal(&[box1, box2], 2);
        let lines: Vec<&str> = joined.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("A"));
        assert!(lines[0].contains("1"));
        assert!(lines[1].contains("B"));
        assert!(lines[1].contains("2"));
    }

    #[test]
    fn test_join_horizontal_different_heights() {
        let box1 = "A\nB\nC";
        let box2 = "1";

        let joined = join_horizontal(&[box1, box2], 1);
        let lines: Vec<&str> = joined.lines().collect();

        assert_eq!(lines.len(), 3); // Takes max height
    }

    #[test]
    fn test_join_vertical() {
        let box1 = "Top";
        let box2 = "Bottom";

        let joined = join_vertical(&[box1, box2]);

        assert!(joined.contains("Top"));
        assert!(joined.contains("Bottom"));
        assert!(joined.contains('\n'));
    }

    #[test]
    fn test_place_center() {
        let content = "X";
        let placed = place(5, 3, Align::Center, Align::Center, content);
        let lines: Vec<&str> = placed.lines().collect();

        assert_eq!(lines.len(), 3);
        // Middle line should have X centered
        assert_eq!(lines[1].trim(), "X");
    }

    #[test]
    fn test_presets() {
        let info = presets::info_box();
        assert_eq!(info.border, BorderStyle::Rounded);
        assert_eq!(info.border_color, Some(Color::Cyan));

        let error = presets::error_box();
        assert_eq!(error.foreground, Some(Color::Red));

        let dialog = presets::dialog_box();
        assert_eq!(dialog.border, BorderStyle::Thick);
        assert_eq!(dialog.align, Align::Center);
    }

    #[test]
    fn test_margin_applied() {
        let style = BoxStyle::new()
            .border(BorderStyle::Normal)
            .margin(Margin::new(1, 0, 1, 2))
            .width(10);

        let output = style.render("Hi", false, true);

        // Left margin should add 2 spaces before border
        assert!(output.contains("  ┌"));
    }

    #[test]
    fn test_min_width() {
        let style = BoxStyle::new().border(BorderStyle::Normal).min_width(20);

        let output = style.render("Hi", false, true);

        // Box should be at least 20 chars wide (+ borders)
        let first_line = output.lines().next().unwrap();
        assert!(first_line.len() >= 22); // 20 + 2 border chars
    }

    #[test]
    fn test_border_has_border() {
        assert!(!BorderStyle::None.has_border());
        assert!(BorderStyle::Normal.has_border());
        assert!(BorderStyle::Rounded.has_border());
        assert!(BorderStyle::Hidden.has_border()); // Hidden still takes space
    }
}
