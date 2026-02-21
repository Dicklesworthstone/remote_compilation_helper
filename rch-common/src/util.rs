//! Shared utilities for RCH.

fn find_value_end(s: &str) -> usize {
    let mut chars = s.chars();
    let mut end = 0;
    let mut in_quote = None;
    let mut escaped = false;

    while let Some(c) = chars.next() {
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
}
