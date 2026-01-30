#[cfg(test)]
mod tests {
    use crate::patterns::classify_command;

    #[test]
    fn test_chained_semicolon_classified() {
        // Multi-command strings are split; compilation sub-commands detected
        let result = classify_command("cargo build ; echo malicious");
        assert!(result.is_compilation, "cargo build sub-command should be detected");
    }

    #[test]
    fn test_chained_and_classified() {
        let result = classify_command("cargo build && echo malicious");
        assert!(result.is_compilation, "cargo build sub-command should be detected");
    }

    #[test]
    fn test_chained_or_classified() {
        let result = classify_command("cargo build || echo failed");
        assert!(result.is_compilation, "cargo build sub-command should be detected");
    }

    #[test]
    fn test_semicolon_in_quotes_allowed() {
        // This is tricky. If the command itself uses quotes correctly, it might be a valid arg.
        // e.g. rustc -C "link-arg=-Wl,-rpath;..." (unlikely to use ; like that but possible)
        // classify_command calls contains_unquoted(';') which handles quotes.

        // Let's test a hypothetical command that uses ; in quotes
        // cargo run --example "foo;bar"
        // This *should* be classified as compilation (cargo run), assuming "foo;bar" is just an arg.
        let result = classify_command("cargo run --example \"foo;bar\"");
        // cargo run is classified as compilation
        assert!(result.is_compilation, "Should allow ; inside quotes");
    }
}
