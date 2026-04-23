//! Shared utilities for RCH.

/// Truncate a string to at most `max_bytes` bytes, snapping back to the nearest
/// UTF-8 character boundary.
///
/// `&s[..n]` panics if byte `n` falls mid-codepoint. Every display path that
/// truncates user- or worker-supplied strings must snap to a char boundary
/// first — otherwise a rogue command like `café build` at exactly the wrong
/// length will crash the whole hook.
pub fn truncate_at_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn find_value_end(s: &str) -> usize {
    let chars = s.chars();
    let mut end = 0;
    let mut in_quote = None;
    let mut escaped = false;

    for c in chars {
        let char_len = c.len_utf8();

        if escaped {
            escaped = false;
            end += char_len;
            continue;
        }

        if c == '\\' {
            escaped = true;
            end += char_len;
            continue;
        }

        if let Some(q) = in_quote {
            if c == q {
                in_quote = None;
            }
            end += char_len;
            continue;
        }

        if c == '"' || c == '\'' {
            in_quote = Some(c);
            end += char_len;
            continue;
        }

        if c.is_whitespace() {
            break;
        }

        end += char_len;
    }
    end
}

/// Mask sensitive patterns in a command string before logging.
///
/// This prevents accidental exposure of API keys, passwords, and tokens
/// that may be present in environment variables or command arguments.
pub fn mask_sensitive_command(cmd: &str) -> String {
    // Patterns to mask (case-insensitive matching would be better, but this is simple)
    // We replace the value part with "***" while keeping the key/flag.
    let patterns = [
        // Environment variable patterns
        ("CARGO_REGISTRY_TOKEN=", "CARGO_REGISTRY_TOKEN=***"),
        ("GITHUB_TOKEN=", "GITHUB_TOKEN=***"),
        ("GH_TOKEN=", "GH_TOKEN=***"),
        ("DATABASE_URL=", "DATABASE_URL=***"),
        ("DB_PASSWORD=", "DB_PASSWORD=***"),
        ("API_KEY=", "API_KEY=***"),
        ("API_SECRET=", "API_SECRET=***"),
        ("SECRET_KEY=", "SECRET_KEY=***"),
        ("SECRET=", "SECRET=***"),
        ("PASSWORD=", "PASSWORD=***"),
        ("PASS=", "PASS=***"),
        ("TOKEN=", "TOKEN=***"),
        ("AUTH_TOKEN=", "AUTH_TOKEN=***"),
        ("ACCESS_TOKEN=", "ACCESS_TOKEN=***"),
        ("PRIVATE_KEY=", "PRIVATE_KEY=***"),
        ("AWS_SECRET_ACCESS_KEY=", "AWS_SECRET_ACCESS_KEY=***"),
        ("AWS_ACCESS_KEY_ID=", "AWS_ACCESS_KEY_ID=***"),
        ("STRIPE_SECRET_KEY=", "STRIPE_SECRET_KEY=***"),
        ("OPENAI_API_KEY=", "OPENAI_API_KEY=***"),
        ("ANTHROPIC_API_KEY=", "ANTHROPIC_API_KEY=***"),
        // Command-line argument patterns (--token, --password, etc.)
        ("--token ", "--token ***"),
        ("--token=", "--token=***"),
        ("--password ", "--password ***"),
        ("--password=", "--password=***"),
        ("--api-key ", "--api-key ***"),
        ("--api-key=", "--api-key=***"),
        ("--secret ", "--secret ***"),
        ("--secret=", "--secret=***"),
    ];

    let mut result = cmd.to_string();
    for (pattern, replacement) in patterns {
        // Loop to handle multiple occurrences of the same pattern
        // Track search position to avoid infinite loop (replacement contains pattern)
        let mut search_start = 0;
        while search_start < result.len() {
            let Some(start) = result[search_start..].find(pattern) else {
                break;
            };
            let abs_start = search_start + start;
            let value_start = abs_start + pattern.len();

            let rest = &result[value_start..];
            let value_end = value_start + find_value_end(rest);

            // Replace the value portion
            let prefix = &result[..abs_start];
            let suffix = &result[value_end..];
            result = format!("{}{}{}", prefix, replacement, suffix);

            // Move past the replacement to avoid re-matching
            search_start = abs_start + replacement.len();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_sensitive_command() {
        let cmd = "cargo run --release TOKEN=secret123 GITHUB_TOKEN=abcdef --token mytoken --password=hidden";
        let masked = mask_sensitive_command(cmd);

        assert!(masked.contains("TOKEN=***"));
        assert!(!masked.contains("secret123"));

        assert!(masked.contains("GITHUB_TOKEN=***"));
        assert!(!masked.contains("abcdef"));

        assert!(masked.contains("--token ***"));
        assert!(!masked.contains("mytoken"));

        assert!(masked.contains("--password=***"));
        assert!(!masked.contains("hidden"));
    }

    #[test]
    fn test_mask_sensitive_command_multiple() {
        let cmd = "TOKEN=a TOKEN=b";
        let masked = mask_sensitive_command(cmd);
        assert_eq!(masked, "TOKEN=*** TOKEN=***");
    }

    #[test]
    fn test_mask_sensitive_command_quoted() {
        let cmd = "cargo run TOKEN=\"my super secret\" --other";
        let masked = mask_sensitive_command(cmd);
        assert_eq!(masked, "cargo run TOKEN=*** --other");
        assert!(!masked.contains("super"));
        assert!(!masked.contains("secret"));
    }

    #[test]
    fn test_truncate_at_char_boundary_short_string_unchanged() {
        assert_eq!(truncate_at_char_boundary("abc", 10), "abc");
        assert_eq!(truncate_at_char_boundary("", 10), "");
        assert_eq!(truncate_at_char_boundary("exactly10!", 10), "exactly10!");
    }

    #[test]
    fn test_truncate_at_char_boundary_ascii() {
        assert_eq!(truncate_at_char_boundary("hello world", 5), "hello");
        assert_eq!(truncate_at_char_boundary("abcdef", 3), "abc");
    }

    #[test]
    fn test_truncate_at_char_boundary_snaps_back_from_mid_codepoint() {
        // "é" is 2 bytes in UTF-8 (0xC3 0xA9). Requesting len=1 would land
        // mid-codepoint; the helper must snap back to 0 rather than panic.
        assert_eq!(truncate_at_char_boundary("é", 1), "");
        // Requesting a boundary past the last codepoint returns the string.
        assert_eq!(truncate_at_char_boundary("é", 2), "é");
        // Mixed ASCII/multi-byte: "café" is 5 bytes. At len=4 we're between
        // "caf" and "é" — safe. At len=3 we're at "caf". At len=2 we're "ca".
        assert_eq!(truncate_at_char_boundary("café", 4), "caf");
        assert_eq!(truncate_at_char_boundary("café", 3), "caf");
        assert_eq!(truncate_at_char_boundary("café", 5), "café");
    }

    #[test]
    fn test_truncate_at_char_boundary_never_panics_on_len_zero() {
        assert_eq!(truncate_at_char_boundary("hello", 0), "");
        assert_eq!(truncate_at_char_boundary("é", 0), "");
    }
}
