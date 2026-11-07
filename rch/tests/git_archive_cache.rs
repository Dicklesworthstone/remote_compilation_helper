//! Process-level tests for the exact cache program embedded by transfer.rs.
//! That program runs before remote Cargo on every clean-overlay job.
#[cfg(unix)]
#[test]
fn git_archive_cache_process_protocol() {
    // The suite asserts cache behavior below trusted ancestors, which only a
    // root-owned sticky base promises on every host. macOS /tmp is an alias.
    let base = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let fixtures = tempfile::Builder::new()
        .prefix("rch-git-archive-cache-")
        .tempdir_in(base)
        .expect("create the fixture base");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/tests/test_git_archive_cache.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .env("TMPDIR", fixtures.path())
        .output()
        .expect("python3 is required for Git archive cache process tests");
    assert!(
        output.status.success(),
        "Git archive cache tests failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
