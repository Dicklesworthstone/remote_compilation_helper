//! .env file support for RCH configuration.
//!
//! Loads configuration from .env and .rch.env files in the project directory.

use anyhow::Result;
use std::path::Path;
use tracing::debug;

/// Parse RCH-related environment variables from .env files.
///
/// Parses from two files in order:
/// 1. `.rch.env` - RCH-specific settings
/// 2. `.env` - General project settings (only RCH_ prefixed vars)
///
/// Returns key-value pairs that are NOT already set in the environment.
/// The caller is responsible for actually setting the environment variables
/// if desired (using unsafe code in a crate that allows it).
///
/// This function only parses and filters - it does not modify the environment.
pub fn load_dotenv(project_dir: &Path) -> Result<Vec<(String, String)>> {
    let mut loaded = Vec::new();

    // Load .rch.env first (RCH-specific settings)
    let rch_env_path = project_dir.join(".rch.env");
    if rch_env_path.exists() {
        debug!("Parsing .rch.env from {:?}", rch_env_path);
        let vars = parse_env_file(&rch_env_path)?;
        for (key, value) in vars {
            if std::env::var(&key).is_err() {
                debug!("  {} = {} (from .rch.env)", key, value);
                loaded.push((key, value));
            }
        }
    }

    // Load .env (only RCH_ prefixed vars)
    let dotenv_path = project_dir.join(".env");
    if dotenv_path.exists() {
        debug!("Parsing .env from {:?}", dotenv_path);
        for (key, value) in parse_env_file(&dotenv_path)? {
            if key.starts_with("RCH_") && std::env::var(&key).is_err() {
                debug!("  {} = {} (from .env)", key, value);
                loaded.push((key, value));
            }
        }
    }

    Ok(loaded)
}

/// Parse a .env file into key-value pairs.
fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)?;
    let mut vars = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse KEY=value
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim();

            // Handle quoted values
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].to_string()
            } else {
                // Remove inline comments (not inside quotes)
                value.split('#').next().unwrap_or("").trim().to_string()
            };

            if key.is_empty() {
                debug!("Skipping empty key at line {}", line_num + 1);
                continue;
            }

            vars.push((key, value));
        }
    }

    Ok(vars)
}

/// Check if any .env files exist in the project directory.
pub fn has_dotenv_files(project_dir: &Path) -> bool {
    project_dir.join(".rch.env").exists() || project_dir.join(".env").exists()
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn set_env(key: &str, value: &str) {
        // SAFETY: Tests run single-threaded, no concurrent access to env vars
        unsafe { std::env::set_var(key, value) };
    }

    fn remove_env(key: &str) {
        // SAFETY: Tests run single-threaded, no concurrent access to env vars
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn test_parse_env_file_basic() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".env");
        fs::write(&env_file, "KEY=value\nANOTHER=123").unwrap();

        let vars = parse_env_file(&env_file).unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0], ("KEY".to_string(), "value".to_string()));
        assert_eq!(vars[1], ("ANOTHER".to_string(), "123".to_string()));
    }

    #[test]
    fn test_parse_env_file_comments() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".env");
        fs::write(
            &env_file,
            "# This is a comment\nKEY=value\n# Another comment\n",
        )
        .unwrap();

        let vars = parse_env_file(&env_file).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], ("KEY".to_string(), "value".to_string()));
    }

    #[test]
    fn test_parse_env_file_quoted() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".env");
        fs::write(&env_file, "DOUBLE=\"hello world\"\nSINGLE='single quoted'").unwrap();

        let vars = parse_env_file(&env_file).unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0], ("DOUBLE".to_string(), "hello world".to_string()));
        assert_eq!(vars[1], ("SINGLE".to_string(), "single quoted".to_string()));
    }

    #[test]
    fn test_parse_env_file_inline_comments() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".env");
        fs::write(&env_file, "KEY=value # this is a comment").unwrap();

        let vars = parse_env_file(&env_file).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], ("KEY".to_string(), "value".to_string()));
    }

    #[test]
    fn test_load_dotenv_only_rch_vars() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".env");
        fs::write(
            &env_file,
            "RCH_LOG_LEVEL=debug\nOTHER_VAR=ignored\nRCH_ENABLED=true",
        )
        .unwrap();

        // Clean up any existing vars
        remove_env("RCH_LOG_LEVEL");
        remove_env("RCH_ENABLED");

        let loaded = load_dotenv(tmp.path()).unwrap();

        // Only RCH_ vars should be loaded
        let keys: Vec<_> = loaded.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"RCH_LOG_LEVEL"));
        assert!(keys.contains(&"RCH_ENABLED"));
        assert!(!keys.contains(&"OTHER_VAR"));

        // Clean up
        remove_env("RCH_LOG_LEVEL");
        remove_env("RCH_ENABLED");
    }

    #[test]
    fn test_load_dotenv_no_override() {
        let tmp = TempDir::new().unwrap();
        let env_file = tmp.path().join(".rch.env");
        fs::write(&env_file, "RCH_PRESET=fromfile").unwrap();

        // Set the var before loading
        set_env("RCH_PRESET", "original");

        let loaded = load_dotenv(tmp.path()).unwrap();

        // Should not override existing var
        assert_eq!(std::env::var("RCH_PRESET").unwrap(), "original");
        assert!(!loaded.iter().any(|(k, _)| k == "RCH_PRESET"));

        // Clean up
        remove_env("RCH_PRESET");
    }
}
