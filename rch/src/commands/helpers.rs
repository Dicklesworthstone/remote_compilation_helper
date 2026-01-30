//! Shared helper functions for RCH commands.

/// Indent each line of text with a given prefix.
pub fn indent_lines(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    for (idx, line) in text.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(prefix);
        out.push_str(line);
    }
    out
}

/// Format a duration in seconds as a human-readable string.
pub fn humanize_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// URL percent-encoding for query parameters.
/// Optimized to avoid allocations by using direct hex conversion.
pub fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indent_lines() {
        assert_eq!(indent_lines("hello\nworld", "  "), "  hello\n  world");
        assert_eq!(indent_lines("single", ">> "), ">> single");
        assert_eq!(indent_lines("", "  "), "");
    }

    #[test]
    fn test_humanize_duration() {
        assert_eq!(humanize_duration(0), "0s");
        assert_eq!(humanize_duration(45), "45s");
        assert_eq!(humanize_duration(65), "1m 5s");
        assert_eq!(humanize_duration(3661), "1h 1m");
        assert_eq!(humanize_duration(90000), "1d 1h");
    }

    #[test]
    fn test_urlencoding_encode() {
        assert_eq!(urlencoding_encode("hello"), "hello");
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
    }
}
