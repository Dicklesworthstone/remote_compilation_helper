//! Nested-runtime prohibition gate (bead G013; Asupersync blocker
//! 44.8; the compat-island policy's hard rule).
//!
//! Long-running daemons own ONE runtime. Nested/re-entrant `block_on`
//! (a runtime entered from inside another's task) deadlocks
//! current-thread executors and breaks timer semantics — the classic
//! production hang. This gate scans every rabs crate's sources for the
//! forbidden patterns and fails CI on any hit outside an explicit,
//! justified allowlist (currently empty).
//!
//! The scan runs in CI like the A002/A004 gates; the detector itself
//! is unit-tested against known-bad snippets (the planted negative) so
//! a scanner regression cannot silently pass everything.

use std::fs;
use std::path::{Path, PathBuf};

/// Forbidden source patterns (nested-runtime entry points).
const FORBIDDEN: [&str; 4] = [
    ".block_on(",
    "block_on(async",
    "Runtime::new()",
    "new_current_thread()",
];

/// Scan one source string; returns the forbidden patterns found on
/// non-comment lines.
fn violations_in(source: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("//!") {
            continue; // comments may DISCUSS the pattern
        }
        for pattern in FORBIDDEN {
            if trimmed.contains(pattern) && !found.contains(&pattern) {
                found.push(pattern);
            }
        }
    }
    found
}

fn rabs_source_files() -> Vec<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(workspace).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.is_dir() && (name.starts_with("rabs-") || name == "rabsd") {
            stack.push(path.join("src"));
        }
    }
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn no_rabs_crate_contains_nested_runtime_patterns() {
    let files = rabs_source_files();
    assert!(
        files.len() >= 10,
        "scanner must actually find the rabs sources (found {})",
        files.len()
    );
    let mut offenders = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file).unwrap();
        let violations = violations_in(&source);
        if !violations.is_empty() {
            offenders.push(format!("{}: {:?}", file.display(), violations));
        }
    }
    assert!(
        offenders.is_empty(),
        "nested-runtime patterns found (one owned runtime per daemon; \
         no nested block_on — Asupersync blocker 44.8):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_detector_catches_known_bad_patterns() {
    // PLANTED NEGATIVE: a scanner regression must not silently pass.
    let known_bad = r"
fn handler(rt: &tokio::runtime::Runtime) {
    let result = rt.block_on(async { fetch().await });
    let nested = tokio::runtime::Runtime::new().unwrap();
    let ct = tokio::runtime::Builder::new_current_thread().build();
}
";
    let violations = violations_in(known_bad);
    assert!(
        violations.contains(&".block_on("),
        "must catch re-entrant block_on"
    );
    assert!(
        violations.contains(&"Runtime::new()"),
        "must catch nested runtime construction"
    );
    // Comment-only mentions do NOT trip the gate (docs may explain
    // the prohibition).
    let comment_only = "// never call .block_on( inside a task\n";
    assert!(violations_in(comment_only).is_empty());
}
