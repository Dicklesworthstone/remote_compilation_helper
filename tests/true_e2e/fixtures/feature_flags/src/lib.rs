//! RCH E2E Test Fixture - Feature Flags
//!
//! This library uses conditional compilation to verify that
//! feature flags are correctly passed to remote workers.

/// Base functionality - always available.
pub fn base_function() -> &'static str {
    "base"
}

/// Verbose functionality - only when "verbose" feature is enabled.
#[cfg(feature = "verbose")]
pub fn verbose_function() -> &'static str {
    "verbose output enabled"
}

/// Extra functionality - only when "extra" feature is enabled.
#[cfg(feature = "extra")]
pub fn extra_function() -> &'static str {
    log::info!("extra function called");
    "extra enabled"
}

/// Check which features are active.
pub fn active_features() -> Vec<&'static str> {
    let mut features = vec!["base"];

    #[cfg(feature = "verbose")]
    features.push("verbose");

    #[cfg(feature = "extra")]
    features.push("extra");

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_function() {
        assert_eq!(base_function(), "base");
    }

    #[test]
    fn test_active_features_includes_base() {
        let features = active_features();
        assert!(features.contains(&"base"));
    }

    #[cfg(feature = "verbose")]
    #[test]
    fn test_verbose_feature() {
        assert_eq!(verbose_function(), "verbose output enabled");
        assert!(active_features().contains(&"verbose"));
    }

    #[cfg(feature = "extra")]
    #[test]
    fn test_extra_feature() {
        assert_eq!(extra_function(), "extra enabled");
        assert!(active_features().contains(&"extra"));
    }
}
