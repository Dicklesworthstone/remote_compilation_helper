//! Nested-runtime prohibition gate (bead G013; Asupersync blocker
//! 44.8; bead `rabs-root-4pidu.8.2`; the compat-island policy's hard rule).
//!
//! Long-running daemons own ONE runtime. Nested/re-entrant `block_on`
//! (a runtime entered from inside another's task) deadlocks
//! current-thread executors and breaks timer semantics, and spawning a
//! fresh runtime per network connection defeats structured concurrency
//! and region accounting.
//!
//! This gate runs in CI alongside the A002/A004 dependency-direction gates and
//! scans non-test production source across every `rabs-*` crate and `rabsd` for
//! BOTH direct `.block_on(` / `Runtime::new()` patterns AND Asupersync
//! runtime-builder / top-level-entry calls (`RuntimeBuilder::current_thread`,
//! `RuntimeBuilder::new(`, `block_on_top_level(`, `block_on_worker_runtime(`).
//!
//! The allowlist is NOT a relaxation: every entry names a verified
//! top-level daemon/service/CLI/listener entry (or caller-owned `&Runtime`
//! driver), carries a written justification, stays anti-rot verified, and
//! is paired with structural anti-regression assertions (e.g., zero
//! per-connection runtimes in `remote_service.rs` and zero subcommand
//! runtime builders in `prepared_jobs/{live,wait,follow}.rs`).

use std::fs;
use std::path::{Path, PathBuf};

/// Forbidden source patterns in production code (nested-runtime entry points
/// and unreviewed runtime construction / top-level blocking entry).
const FORBIDDEN: [&str; 8] = [
    ".block_on(",
    "block_on(async",
    "Runtime::new()",
    "new_current_thread()",
    "RuntimeBuilder::current_thread",
    "RuntimeBuilder::new(",
    "block_on_top_level(",
    "block_on_worker_runtime(",
];

/// Justified allowlist: production files whose runtime entry is an explicit
/// top-level process/service/client/listener owner (never nested inside an
/// active async task, and never per-connection).
///
/// Tuple = (path suffix from workspace root, justification).
const ALLOWED_RUNTIME_ENTRIES: &[(&str, &str)] = &[
    (
        "rabs-asupersync/src/daemon_runtime.rs",
        "owns the rabsd daemon's ONE top-level current-thread runtime and defines the dynamic Cx::current().is_none() guard in block_on_top_level",
    ),
    (
        "rabs-wkr/src/main.rs",
        "defines the rabs-wkr worker binary's dynamic Cx::current().is_none() guard in block_on_worker_runtime",
    ),
    (
        "rabs-wkr/src/reconnect.rs",
        "owns the rabs-wkr worker process's single top-level runtime driving the ATP reconnect/session loop from main",
    ),
    (
        "rabsd/src/coord/canonical_local/remote_service.rs",
        "owns the --canonical-compile-remote-service server's ONE shared bounded multi-thread runtime across all accepted TLS sessions (zero per-connection runtimes)",
    ),
    (
        "rabsd/src/coord/canonical_local/remote_service/client.rs",
        "owns the standalone --canonical-compile-remote CLI client invocation's single top-level runtime",
    ),
    (
        "rabsd/src/coord/remote_dependency_transport/standby.rs",
        "owns the dedicated standby worker-listener OS thread's single runtime (created outside any async task)",
    ),
    (
        "rabsd/src/coord/secure_worker_delivery.rs",
        "drives a caller-owned &Runtime via block_on_top_level without constructing any runtime of its own",
    ),
    (
        "rabsd/src/coord/secure_worker_delivery/interrupt.rs",
        "drives a caller-owned &Runtime via block_on_top_level without constructing any runtime of its own",
    ),
    (
        "rabsd/src/prepared_jobs.rs",
        "owns the single consolidated ClientSession runtime for standalone rabsd --job-* CLI subcommands",
    ),
    (
        "rabsd/src/worker_exec.rs",
        "owns the standalone --worker-exec-tls / --worker-build-tls CLI subcommand's single top-level runtime",
    ),
];

/// Path suffixes above are matched against the workspace-relative path.
fn is_allowed_runtime_entry(path: &Path) -> bool {
    let rendered = path.to_string_lossy();
    ALLOWED_RUNTIME_ENTRIES
        .iter()
        .any(|(suffix, _)| rendered.ends_with(suffix))
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_test_only_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name == "tests.rs" || name.ends_with("_tests.rs")
}

/// Skip a Rust raw string literal starting at `bytes[i]` (`r`, `br`, or `cr`).
/// Returns the byte index immediately after the closing delimiter if `i` starts
/// a raw string literal, or `None` if it is an ordinary identifier.
fn skip_raw_string(bytes: &[u8], i: usize) -> Option<usize> {
    if i > 0 && is_ident_char(bytes[i - 1]) {
        return None;
    }
    let mut j = i;
    if bytes.get(j) == Some(&b'b') || bytes.get(j) == Some(&b'c') {
        j += 1;
    }
    if bytes.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0usize;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let mut close = 0usize;
            while close < hashes && bytes.get(j + 1 + close) == Some(&b'#') {
                close += 1;
            }
            if close == hashes {
                return Some(j + 1 + hashes);
            }
        }
        j += 1;
    }
    Some(bytes.len())
}

/// Skip a normal `"..."` string literal starting at `bytes[i] == b'"'`.
fn skip_normal_string(bytes: &[u8], mut i: usize) -> usize {
    i += 1; // opening quote
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == b'"' {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

/// Skip a Rust char literal starting at `bytes[i] == b'\''`, without misreading
/// lifetimes like `'a` or `'runtime`.
fn skip_char_literal(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'\'') {
        return None;
    }
    let next = *bytes.get(i + 1)?;
    if next == b'\\' {
        let mut j = i + 2;
        if j < bytes.len() {
            j += 1;
        }
        while j < bytes.len() && bytes[j] != b'\'' && bytes[j] != b'\n' {
            j += 1;
        }
        return (bytes.get(j) == Some(&b'\'')).then_some(j + 1);
    }
    // Single scalar value followed immediately by closing `'`.
    let rest = std::str::from_utf8(&bytes[i + 1..]).ok()?;
    let ch = rest.chars().next()?;
    if ch == '\'' || ch == '\n' {
        return None;
    }
    let close = i + 1 + ch.len_utf8();
    (bytes.get(close) == Some(&b'\'')).then_some(close + 1)
}

/// Skip a `/* ... */` block comment (supporting Rust nesting) starting at `i`.
fn skip_block_comment(bytes: &[u8], mut i: usize) -> usize {
    i += 2;
    let mut depth = 1usize;
    while i < bytes.len() && depth > 0 {
        if bytes.get(i..i + 2) == Some(b"/*") {
            depth += 1;
            i += 2;
        } else if bytes.get(i..i + 2) == Some(b"*/") {
            depth -= 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    i
}

/// Match an outer (`#[...]`) or inner (`#![...]`) attribute starting at `i`.
/// Returns `(is_inner, inner_trimmed, next_index)`.
fn parse_attribute(bytes: &[u8], i: usize) -> Option<(bool, String, usize)> {
    if bytes.get(i) != Some(&b'#') {
        return None;
    }
    let mut j = i + 1;
    let is_inner = bytes.get(j) == Some(&b'!');
    if is_inner {
        j += 1;
    }
    while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
        j += 1;
    }
    if bytes.get(j) != Some(&b'[') {
        return None;
    }
    let start = j + 1;
    let mut depth = 1usize;
    j += 1;
    while j < bytes.len() && depth > 0 {
        if let Some(next) = skip_raw_string(bytes, j) {
            j = next;
        } else if bytes[j] == b'"' {
            j = skip_normal_string(bytes, j);
        } else if bytes[j] == b'[' {
            depth += 1;
            j += 1;
        } else if bytes[j] == b']' {
            depth -= 1;
            j += 1;
        } else {
            j += 1;
        }
    }
    let end = j.saturating_sub(1);
    let compact: String = std::str::from_utf8(&bytes[start..end])
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    Some((is_inner, compact, j))
}

/// Skip whitespace, comments, and consecutive outer attributes (`#[...]`).
fn skip_ws_comments_and_attrs(bytes: &[u8], mut i: usize) -> usize {
    loop {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if bytes.get(i..i + 2) == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes.get(i..i + 2) == Some(b"/*") {
            i = skip_block_comment(bytes, i);
        } else if let Some((false, _, next)) = parse_attribute(bytes, i) {
            i = next;
        } else {
            return i;
        }
    }
}

/// Peek whether the tokens starting at `i` introduce a full Rust item
/// (`mod`, `fn`, `struct`, `enum`, `trait`, `impl`, `type`, `use`, `extern`,
/// `static`, `const`, `macro_rules`) as opposed to a struct field or variant.
fn starts_item_declaration(bytes: &[u8], mut i: usize) -> bool {
    loop {
        i = skip_ws_comments_and_attrs(bytes, i);
        let start = i;
        while bytes.get(i).is_some_and(|b| is_ident_char(*b)) {
            i += 1;
        }
        let word = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
        match word {
            "pub" => {
                // Skip optional visibility restriction `pub(crate)` / `pub(super)`.
                i = skip_ws_comments_and_attrs(bytes, i);
                if bytes.get(i) == Some(&b'(') {
                    let mut depth = 1usize;
                    i += 1;
                    while i < bytes.len() && depth > 0 {
                        match bytes[i] {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        i += 1;
                    }
                }
            }
            "async" | "unsafe" | "default" => {}
            "const" => {
                // `const fn` / `const NAME:` is an item, never a struct field.
                return true;
            }
            "mod" | "fn" | "struct" | "enum" | "trait" | "impl" | "type" | "use" | "extern"
            | "static" | "macro_rules" => return true,
            _ => return false,
        }
    }
}

/// Skip the single Rust item, struct field, or enum variant annotated by
/// `#[cfg(test)]`, starting right after the attribute's closing `]`.
fn skip_cfg_test_target(bytes: &[u8], start: usize) -> usize {
    let mut i = skip_ws_comments_and_attrs(bytes, start);
    let is_item = starts_item_declaration(bytes, i);
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut seen_open_brace = false;

    while i < bytes.len() {
        if bytes.get(i..i + 2) == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes.get(i..i + 2) == Some(b"/*") {
            i = skip_block_comment(bytes, i);
            continue;
        }
        if let Some(next) = skip_raw_string(bytes, i) {
            i = next;
            continue;
        }
        if bytes[i] == b'"' {
            i = skip_normal_string(bytes, i);
            continue;
        }
        if let Some(next) = skip_char_literal(bytes, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => {
                brace_depth += 1;
                seen_open_brace = true;
            }
            b'}' => {
                if brace_depth == 0 {
                    // Closing brace of an enclosing struct/enum/module after a
                    // field/variant without a trailing comma: leave it intact.
                    return i;
                }
                brace_depth -= 1;
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    return i + 1;
                }
            }
            b';' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                return i + 1;
            }
            b',' if !is_item
                && !seen_open_brace
                && brace_depth == 0
                && paren_depth == 0
                && bracket_depth == 0 =>
            {
                return i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// True iff a whitespace-stripped attribute is strictly test-only:
/// `cfg(test)` or `cfg(all(..., test, ...))` with `test` as a top-level term
/// inside `all(...)`. Never matches `cfg(any(...))` or `cfg(not(test))`,
/// because those can compile in production builds.
fn is_cfg_test_attr(attr: &str) -> bool {
    if attr == "cfg(test)" {
        return true;
    }
    let Some(inner) = attr
        .strip_prefix("cfg(all(")
        .and_then(|s| s.strip_suffix("))"))
    else {
        return false;
    };
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if &inner[start..idx] == "test" {
                    return true;
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    depth == 0 && &inner[start..] == "test"
}

/// Extract production (non-comment, non-`#[cfg(test)]`) Rust source text.
/// Preserves string literals verbatim so forbidden calls are never masked,
/// while stripping comments and `#[cfg(test)]` items cleanly without skipping
/// production code that appears later in the same file.
fn production_code_only(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes.get(i..i + 2) == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes.get(i..i + 2) == Some(b"/*") {
            let next = skip_block_comment(bytes, i);
            for &b in &bytes[i..next] {
                if b == b'\n' {
                    out.push('\n');
                }
            }
            i = next;
            continue;
        }
        if let Some(next) = skip_raw_string(bytes, i) {
            out.push_str(&source[i..next]);
            i = next;
            continue;
        }
        if bytes[i] == b'"' {
            let next = skip_normal_string(bytes, i);
            out.push_str(&source[i..next]);
            i = next;
            continue;
        }
        if let Some(next) = skip_char_literal(bytes, i) {
            out.push_str(&source[i..next]);
            i = next;
            continue;
        }
        if let Some((is_inner, attr, next)) = parse_attribute(bytes, i)
            && is_cfg_test_attr(&attr)
        {
            if is_inner {
                // File-level `#![cfg(test)]`: entire module is test-only.
                return String::new();
            }
            i = skip_cfg_test_target(bytes, next);
            out.push('\n');
            continue;
        }
        let ch = source[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Scan one source string's production code; returns the forbidden patterns
/// found outside comments and `#[cfg(test)]` items.
fn violations_in(source: &str) -> Vec<&'static str> {
    let prod = production_code_only(source);
    let mut found = Vec::new();
    for line in prod.lines() {
        for pattern in FORBIDDEN {
            if line.contains(pattern) && !found.contains(&pattern) {
                found.push(pattern);
            }
        }
    }
    found
}

fn count_pattern_in_production(source: &str, pattern: &str) -> usize {
    production_code_only(source).matches(pattern).count()
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
            } else if path.extension().is_some_and(|e| e == "rs") && !is_test_only_file(&path) {
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
        if violations.is_empty() {
            continue;
        }
        if is_allowed_runtime_entry(file) {
            continue; // justified top-level entry (see allowlist)
        }
        offenders.push(format!("{}: {:?}", file.display(), violations));
    }
    assert!(
        offenders.is_empty(),
        "nested-runtime or unreviewed runtime-builder patterns found \
         (one owned runtime per daemon; no nested block_on — Asupersync blocker 44.8):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn remote_service_and_client_subcommands_never_build_per_connection_or_duplicate_runtimes() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();

    // remote_service.rs must keep ONE bounded RuntimeBuilder::new() and ZERO
    // RuntimeBuilder::current_thread calls in production code (no per-session runtime).
    let remote_service =
        fs::read_to_string(workspace.join("rabsd/src/coord/canonical_local/remote_service.rs"))
            .unwrap();
    assert_eq!(
        count_pattern_in_production(&remote_service, "RuntimeBuilder::current_thread"),
        0,
        "remote_service.rs must never build per-connection current_thread runtimes"
    );
    assert_eq!(
        count_pattern_in_production(&remote_service, "RuntimeBuilder::new("),
        1,
        "remote_service.rs must build exactly ONE shared bounded runtime"
    );

    // prepared_jobs/{live,wait,follow}.rs must reuse prepared_jobs::ClientSession
    // rather than building ad-hoc runtimes.
    for rel in [
        "rabsd/src/prepared_jobs/live.rs",
        "rabsd/src/prepared_jobs/wait.rs",
        "rabsd/src/prepared_jobs/follow.rs",
    ] {
        let src = fs::read_to_string(workspace.join(rel)).unwrap();
        assert!(
            violations_in(&src).is_empty(),
            "{rel} must not construct its own runtime or call block_on directly"
        );
    }

    // secure_worker_delivery drives a caller-owned &Runtime; it must build zero runtimes.
    for rel in [
        "rabsd/src/coord/secure_worker_delivery.rs",
        "rabsd/src/coord/secure_worker_delivery/interrupt.rs",
    ] {
        let src = fs::read_to_string(workspace.join(rel)).unwrap();
        assert_eq!(
            count_pattern_in_production(&src, "RuntimeBuilder::"),
            0,
            "{rel} must only borrow a caller-owned Runtime, never construct one"
        );
    }
}

#[test]
fn the_detector_catches_known_bad_patterns_including_after_cfg_test_blocks() {
    // PLANTED NEGATIVE: a scanner regression must not silently pass.
    let known_bad = r#"
#[cfg(test)]
mod earlier_tests {
    fn test_only() {
        let ok_in_test = RuntimeBuilder::current_thread().build().unwrap();
        let brace_in_str = "}}";
        let _ = (ok_in_test, brace_in_str);
    }
}

fn handler(rt: &tokio::runtime::Runtime) {
    let result = rt.block_on(async { fetch().await });
    let nested = tokio::runtime::Runtime::new().unwrap();
    let ct = tokio::runtime::Builder::new_current_thread().build();
    let asup_ct = asupersync::runtime::RuntimeBuilder::current_thread().build();
    let asup_mt = asupersync::runtime::RuntimeBuilder::new().build();
    let top = block_on_top_level(rt, async {});
    let wkr = block_on_worker_runtime(rt, async {});
    let _ = (result, nested, ct, asup_ct, asup_mt, top, wkr);
}
"#;
    let violations = violations_in(known_bad);
    for expected in FORBIDDEN {
        assert!(
            violations.contains(&expected),
            "must catch {expected:?} even after a #[cfg(test)] module (got {violations:?})"
        );
    }

    // Comment-only and test-only mentions do NOT trip the gate.
    let safe_only = r#"
// never call .block_on( or RuntimeBuilder::current_thread inside a task
/* block_on_top_level( nested /* RuntimeBuilder::new( */ ) */
struct S {
    #[cfg(test)]
    test_field: u32,
    live_field: u32,
}
#[cfg(test)]
mod tests {
    fn helper() {
        let rt = RuntimeBuilder::current_thread().build().unwrap();
        block_on_top_level(&rt, async {});
    }
}
#[cfg(all(test, unix))]
mod unix_only_tests {
    fn helper() {
        let _ = RuntimeBuilder::current_thread().build();
    }
}
"#;
    assert!(
        violations_in(safe_only).is_empty(),
        "comments and #[cfg(test)] items must not false-positive: {:?}",
        violations_in(safe_only)
    );

    // Non-strict cfg forms (any / not(test)) compile in production and MUST still be caught.
    let non_strict_cfg = r#"
#[cfg(any(test, unix))]
fn runs_in_prod_too() {
    let _ = RuntimeBuilder::current_thread().build();
}
#[cfg(all(not(test), unix))]
fn runs_only_in_prod() {
    let _ = RuntimeBuilder::new().build();
}
"#;
    let non_strict_hits = violations_in(non_strict_cfg);
    assert!(
        non_strict_hits.contains(&"RuntimeBuilder::current_thread"),
        "cfg(any(test, unix)) must be scanned as production: {non_strict_hits:?}"
    );
    assert!(
        non_strict_hits.contains(&"RuntimeBuilder::new("),
        "cfg(all(not(test), unix)) must be scanned as production: {non_strict_hits:?}"
    );
}

#[test]
fn allowlist_entries_point_at_live_pattern_sites() {
    // Anti-rot guard: an allowlist entry whose file vanished or no
    // longer contains any forbidden pattern is STALE — it would mask
    // future hits in a reused path and must be pruned by a human.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    assert!(
        !ALLOWED_RUNTIME_ENTRIES.is_empty(),
        "allowlist entries were removed; if the runtime entries moved, \
         update them — never delete the guard silently"
    );
    for (suffix, justification) in ALLOWED_RUNTIME_ENTRIES {
        let path = workspace.join(suffix);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("allowlisted file {suffix} unreadable: {e}"));
        let violations = violations_in(&source);
        assert!(
            !violations.is_empty(),
            "stale allowlist entry {suffix} ({justification}): the file \
             no longer contains a runtime entry — prune the entry"
        );
    }
}
