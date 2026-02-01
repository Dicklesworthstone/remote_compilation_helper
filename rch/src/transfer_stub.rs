//! Windows/non-Unix stub for the transfer module.
//!
//! The full transfer pipeline depends on SSH and rsync which are Unix-only.
//! This stub provides the cross-platform utility functions that other modules
//! need (project ID extraction, .rchignore parsing) without pulling in any
//! Unix dependencies.

use std::path::Path;

/// Parse a `.rchignore` file into a list of exclude patterns.
///
/// Format:
/// - One pattern per line
/// - Lines starting with # are comments
/// - Empty lines and whitespace-only lines are ignored
/// - Leading/trailing whitespace is trimmed from patterns
///
/// Note: Unlike .gitignore, negation patterns (starting with !) are not
/// supported and will be treated as literal patterns.
pub fn parse_rchignore(path: &Path) -> std::io::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_rchignore_content(&content))
}

/// Parse .rchignore content (for testing).
pub fn parse_rchignore_content(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
}

/// Validate a project identifier for safe use in file paths.
fn sanitize_project_id(name: &str) -> String {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('-')
    {
        return "unknown".to_string();
    }

    let is_safe = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !name.starts_with('.');

    if is_safe {
        name.to_string()
    } else {
        let sanitized: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let result = sanitized.trim_start_matches('.');
        if result.is_empty() {
            "unknown".to_string()
        } else {
            result.to_string()
        }
    }
}

/// Get the project identifier from a path.
///
/// Extracts the directory name and sanitizes it for safe use in remote paths.
/// Returns "unknown" if the path is invalid or the name contains dangerous characters.
pub fn project_id_from_path(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    sanitize_project_id(name)
}
