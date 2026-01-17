use std::path::Path;

pub fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected to find '{needle}' in output, got: {haystack}"
    );
}

pub fn assert_path_exists(path: &Path) {
    assert!(path.exists(), "Expected path to exist: {}", path.display());
}
