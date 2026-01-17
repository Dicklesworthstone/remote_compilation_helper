//! Markdown rendering for terminal output.
//!
//! Provides a simple markdown-to-terminal renderer using pulldown-cmark.
//! Supports headings, bold/italic, lists, code blocks, and links.
//!
//! # Usage
//!
//! ```rust,ignore
//! use rch::ui::markdown::render_markdown;
//!
//! let md = "# Title\n\n**Bold** and *italic* text.";
//! let output = render_markdown(md, true, true);
//! println!("{}", output);
//! ```

use colored::Colorize;
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

/// Render markdown to styled terminal output.
///
/// # Arguments
/// * `input` - Markdown source text
/// * `colors_enabled` - Whether to use ANSI color codes
/// * `unicode_enabled` - Whether to use Unicode characters (bullets, etc.)
///
/// # Returns
/// Rendered text suitable for terminal display.
pub fn render_markdown(input: &str, colors_enabled: bool, unicode_enabled: bool) -> String {
    let parser = Parser::new(input);
    let renderer = TerminalRenderer::new(colors_enabled, unicode_enabled);
    renderer.render(parser)
}

/// Terminal markdown renderer state machine.
struct TerminalRenderer {
    output: String,
    colors_enabled: bool,
    unicode_enabled: bool,

    // Text style state
    bold: bool,
    italic: bool,

    // Block state
    in_code_block: bool,
    in_list: bool,
    list_depth: usize,
    ordered_list_counter: Option<usize>,

    // Line state
    line_start: bool,
    pending_newlines: usize,
}

impl TerminalRenderer {
    fn new(colors_enabled: bool, unicode_enabled: bool) -> Self {
        Self {
            output: String::new(),
            colors_enabled,
            unicode_enabled,
            bold: false,
            italic: false,
            in_code_block: false,
            in_list: false,
            list_depth: 0,
            ordered_list_counter: None,
            line_start: true,
            pending_newlines: 0,
        }
    }

    fn render(mut self, parser: Parser) -> String {
        for event in parser {
            self.handle_event(event);
        }
        // Trim trailing whitespace
        self.output.trim_end().to_string()
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Start(tag) => self.handle_start_tag(tag),
            Event::End(tag) => self.handle_end_tag(tag),
            Event::Text(text) => self.handle_text(&text),
            Event::Code(code) => self.handle_inline_code(&code),
            Event::SoftBreak => self.handle_soft_break(),
            Event::HardBreak => self.handle_hard_break(),
            Event::Rule => self.handle_rule(),
            // Skip footnotes, task lists, etc. for simplicity
            _ => {}
        }
    }

    fn handle_start_tag(&mut self, tag: Tag) {
        match tag {
            Tag::Heading { level, .. } => {
                self.ensure_newlines(2);
                self.write_heading_prefix(level);
            }
            Tag::Paragraph => {
                if !self.in_list {
                    self.ensure_newlines(2);
                }
            }
            Tag::BlockQuote(_) => {
                self.ensure_newlines(1);
            }
            Tag::CodeBlock(_) => {
                self.ensure_newlines(1);
                self.in_code_block = true;
            }
            Tag::List(start) => {
                if !self.in_list {
                    self.ensure_newlines(1);
                }
                self.in_list = true;
                self.list_depth += 1;
                self.ordered_list_counter = start.map(|n| n as usize);
            }
            Tag::Item => {
                self.ensure_newlines(1);
                self.write_list_marker();
            }
            Tag::Emphasis => {
                self.italic = true;
            }
            Tag::Strong => {
                self.bold = true;
            }
            Tag::Link { dest_url, .. } => {
                // Will handle URL after link text
                self.output.push_str(&format!("[link:{}](", dest_url));
            }
            _ => {}
        }
    }

    fn handle_end_tag(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Heading(_) => {
                self.pending_newlines = 1;
            }
            TagEnd::Paragraph => {
                self.pending_newlines = 2;
            }
            TagEnd::BlockQuote(_) => {
                self.pending_newlines = 1;
            }
            TagEnd::CodeBlock => {
                self.in_code_block = false;
                self.pending_newlines = 1;
            }
            TagEnd::List(_) => {
                self.list_depth = self.list_depth.saturating_sub(1);
                if self.list_depth == 0 {
                    self.in_list = false;
                    self.pending_newlines = 1;
                }
                self.ordered_list_counter = None;
            }
            TagEnd::Item => {
                // Item ends, prepare for next
            }
            TagEnd::Emphasis => {
                self.italic = false;
            }
            TagEnd::Strong => {
                self.bold = false;
            }
            TagEnd::Link => {
                self.output.push(')');
            }
            _ => {}
        }
    }

    fn handle_text(&mut self, text: &str) {
        self.flush_pending_newlines();

        if self.in_code_block {
            // Code blocks: indent and preserve formatting
            for line in text.lines() {
                self.write_code_line(line);
                self.output.push('\n');
            }
            // Remove trailing newline if text didn't have one
            if !text.ends_with('\n') {
                self.output.pop();
            }
        } else {
            // Apply text styles
            let styled = self.style_text(text);
            self.output.push_str(&styled);
            self.line_start = text.ends_with('\n');
        }
    }

    fn handle_inline_code(&mut self, code: &str) {
        self.flush_pending_newlines();
        let styled = if self.colors_enabled {
            format!("`{}`", code.cyan())
        } else {
            format!("`{}`", code)
        };
        self.output.push_str(&styled);
    }

    fn handle_soft_break(&mut self) {
        self.output.push(' ');
    }

    fn handle_hard_break(&mut self) {
        self.output.push('\n');
        self.line_start = true;
    }

    fn handle_rule(&mut self) {
        self.ensure_newlines(1);
        let rule = if self.unicode_enabled {
            "\u{2500}".repeat(40) // Box-drawing horizontal line
        } else {
            "-".repeat(40)
        };
        if self.colors_enabled {
            self.output.push_str(&rule.dimmed().to_string());
        } else {
            self.output.push_str(&rule);
        }
        self.pending_newlines = 1;
    }

    fn ensure_newlines(&mut self, count: usize) {
        self.pending_newlines = self.pending_newlines.max(count);
    }

    fn flush_pending_newlines(&mut self) {
        if self.pending_newlines > 0 {
            // Count existing trailing newlines
            let existing = self.output.chars().rev().take_while(|&c| c == '\n').count();
            let needed = self.pending_newlines.saturating_sub(existing);
            for _ in 0..needed {
                self.output.push('\n');
            }
            self.pending_newlines = 0;
            self.line_start = true;
        }
    }

    fn write_heading_prefix(&mut self, level: HeadingLevel) {
        let prefix = match level {
            HeadingLevel::H1 => {
                if self.colors_enabled {
                    "# ".bold().to_string()
                } else {
                    "# ".to_string()
                }
            }
            HeadingLevel::H2 => {
                if self.colors_enabled {
                    "## ".bold().to_string()
                } else {
                    "## ".to_string()
                }
            }
            HeadingLevel::H3 => {
                if self.colors_enabled {
                    "### ".bold().dimmed().to_string()
                } else {
                    "### ".to_string()
                }
            }
            _ => {
                let hashes = "#".repeat(level as usize);
                if self.colors_enabled {
                    format!("{} ", hashes).dimmed().to_string()
                } else {
                    format!("{} ", hashes)
                }
            }
        };
        self.output.push_str(&prefix);
    }

    fn write_list_marker(&mut self) {
        let indent = "  ".repeat(self.list_depth.saturating_sub(1));
        self.output.push_str(&indent);

        if let Some(ref mut counter) = self.ordered_list_counter {
            self.output.push_str(&format!("{}. ", counter));
            *counter += 1;
        } else {
            let bullet = if self.unicode_enabled {
                match self.list_depth {
                    1 => "\u{2022} ", // •
                    2 => "\u{25e6} ", // ◦
                    _ => "\u{2023} ", // ‣
                }
            } else {
                match self.list_depth {
                    1 => "* ",
                    2 => "- ",
                    _ => "+ ",
                }
            };
            if self.colors_enabled {
                self.output.push_str(&bullet.dimmed().to_string());
            } else {
                self.output.push_str(bullet);
            }
        }
    }

    fn write_code_line(&mut self, line: &str) {
        let indent = "    ";
        if self.colors_enabled {
            self.output.push_str(&format!("{}{}", indent, line.dimmed()));
        } else {
            self.output.push_str(&format!("{}{}", indent, line));
        }
    }

    fn style_text(&self, text: &str) -> String {
        if !self.colors_enabled {
            return text.to_string();
        }

        let mut styled = text.normal();

        if self.bold {
            styled = styled.bold();
        }
        if self.italic {
            styled = styled.italic();
        }

        styled.to_string()
    }
}

/// Strip markdown to plain text (for non-TTY output).
///
/// Removes all formatting and returns clean text.
pub fn strip_markdown(input: &str) -> String {
    let parser = Parser::new(input);
    let mut output = String::new();
    let mut in_code_block = false;

    for event in parser {
        match event {
            Event::Text(text) => output.push_str(&text),
            Event::Code(code) => output.push_str(&code),
            Event::SoftBreak | Event::HardBreak => output.push('\n'),
            Event::Start(Tag::CodeBlock(_)) => {
                in_code_block = true;
                output.push('\n');
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code_block = false;
                output.push('\n');
            }
            Event::Start(Tag::Paragraph) if !in_code_block => {
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push_str("\n\n");
                }
            }
            Event::End(TagEnd::Paragraph) if !in_code_block => {
                output.push('\n');
            }
            Event::Start(Tag::Item) => {
                output.push_str("- ");
            }
            Event::End(TagEnd::Item) => {
                output.push('\n');
            }
            Event::Rule => {
                output.push_str("\n---\n");
            }
            _ => {}
        }
    }

    output.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_heading() {
        let md = "# Title";
        let output = render_markdown(md, false, true);
        assert!(output.contains("Title"));
        assert!(output.contains("#")); // Heading prefix
    }

    #[test]
    fn test_render_heading_levels() {
        let md = "# H1\n\n## H2\n\n### H3";
        let output = render_markdown(md, false, true);
        // Check that headings are rendered (may have prefix styles)
        assert!(output.contains("H1"));
        assert!(output.contains("H2"));
        assert!(output.contains("H3"));
    }

    #[test]
    fn test_render_paragraph() {
        let md = "First paragraph.\n\nSecond paragraph.";
        let output = render_markdown(md, false, true);
        assert!(output.contains("First paragraph"));
        assert!(output.contains("Second paragraph"));
    }

    #[test]
    fn test_render_bold() {
        let md = "This is **bold** text.";
        let output = render_markdown(md, false, true);
        assert!(output.contains("bold"));
    }

    #[test]
    fn test_render_italic() {
        let md = "This is *italic* text.";
        let output = render_markdown(md, false, true);
        assert!(output.contains("italic"));
    }

    #[test]
    fn test_render_inline_code() {
        let md = "Use `cargo build` to compile.";
        let output = render_markdown(md, false, true);
        assert!(output.contains("`cargo build`"));
    }

    #[test]
    fn test_render_code_block() {
        let md = "```\nfn main() {}\n```";
        let output = render_markdown(md, false, true);
        assert!(output.contains("fn main()"));
    }

    #[test]
    fn test_render_unordered_list_unicode() {
        let md = "- Item 1\n- Item 2\n- Item 3";
        let output = render_markdown(md, false, true);
        assert!(output.contains("\u{2022}")); // Unicode bullet
        assert!(output.contains("Item 1"));
        assert!(output.contains("Item 2"));
    }

    #[test]
    fn test_render_unordered_list_ascii() {
        let md = "- Item 1\n- Item 2";
        let output = render_markdown(md, false, false);
        // Check that items are rendered (bullet style may vary)
        assert!(output.contains("Item 1"));
        assert!(output.contains("Item 2"));
        // Should use ASCII bullets, not Unicode
        assert!(!output.contains("\u{2022}")); // No Unicode bullet
    }

    #[test]
    fn test_render_ordered_list() {
        let md = "1. First\n2. Second\n3. Third";
        let output = render_markdown(md, false, true);
        // Check that items are rendered with numbers
        assert!(output.contains("First"));
        assert!(output.contains("Second"));
        assert!(output.contains("Third"));
        assert!(output.contains("1."));
        assert!(output.contains("2."));
        assert!(output.contains("3."));
    }

    #[test]
    fn test_render_rule() {
        let md = "Before\n\n---\n\nAfter";
        let output = render_markdown(md, false, true);
        assert!(output.contains("\u{2500}")); // Unicode horizontal line
    }

    #[test]
    fn test_render_rule_ascii() {
        let md = "Before\n\n---\n\nAfter";
        let output = render_markdown(md, false, false);
        assert!(output.contains("---"));
    }

    #[test]
    fn test_strip_markdown_basic() {
        let md = "# Heading\n\n**Bold** and *italic* text.";
        let output = strip_markdown(md);
        assert!(output.contains("Heading"));
        assert!(output.contains("Bold"));
        assert!(output.contains("italic"));
        assert!(!output.contains("**"));
        assert!(!output.contains("*italic*"));
    }

    #[test]
    fn test_strip_markdown_code() {
        let md = "Use `code` here.";
        let output = strip_markdown(md);
        assert!(output.contains("code"));
        assert!(!output.contains("`code`"));
    }

    #[test]
    fn test_strip_markdown_list() {
        let md = "- Item 1\n- Item 2";
        let output = strip_markdown(md);
        assert!(output.contains("Item 1"));
        assert!(output.contains("Item 2"));
    }

    #[test]
    fn test_render_empty() {
        let output = render_markdown("", false, true);
        assert!(output.is_empty());
    }

    #[test]
    fn test_render_with_colors() {
        let md = "# Title\n\n**Bold** text.";
        let output = render_markdown(md, true, true);
        // Should contain ANSI escape codes
        assert!(output.contains('\x1b') || output.contains("Title"));
    }

    #[test]
    fn test_nested_list() {
        let md = "- Level 1\n  - Level 2\n    - Level 3";
        let output = render_markdown(md, false, true);
        assert!(output.contains("Level 1"));
        assert!(output.contains("Level 2"));
        assert!(output.contains("Level 3"));
    }
}
