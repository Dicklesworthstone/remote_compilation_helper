//! N001 fixture build script: emits the directive surface a run-cache would
//! have to reproduce EXACTLY, and records the invocation facts a shim or
//! driver interception must preserve (executable identity, jobserver
//! descriptors, environment contract).
//!
//! std-only by design: the fixture must compile identically on stable,
//! beta, and nightly without features or lint configuration.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));

    // Invocation facts: what ran, with what descriptors.
    let exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_owned());
    let argv: Vec<String> = env::args().collect();
    let makeflags = env::var("CARGO_MAKEFLAGS").ok();
    let jobserver_fds = makeflags.as_deref().and_then(|flags| {
        flags
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix("--jobserver-fds="))
            .map(str::to_owned)
    });

    // One JSON object, hand-rolled (std-only fixture; no deps allowed).
    let mut record = String::with_capacity(256);
    record.push('{');
    push_str_field(&mut record, "exe", &exe);
    record.push_str(",\"argv\":[");
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            record.push(',');
        }
        push_str_field(&mut record, "", a);
    }
    record.push_str("]");
    record.push_str(",\"has_cargo_makeflags\":");
    record.push_str(if makeflags.is_some() { "true" } else { "false" });
    record.push_str(",\"jobserver_fds\":\"");
    record.push_str(jobserver_fds.as_deref().unwrap_or(""));
    record.push_str("\"}");
    record.push('\n');

    fs::write(out_dir.join("probe.json"), record).expect("write probe.json");

    // The generated output a run-cache must reproduce byte-identically.
    fs::write(
        out_dir.join("generated.rs"),
        "pub fn generated() -> u32 {\n    42\n}\n",
    )
    .expect("write generated.rs");

    // Directive surface: rerun triggers + env injection.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=N001_PROBE_VAR");
    println!("cargo:rustc-env=N001_GENERATED=1");
}

/// Append `"name":"value"` (empty name for bare array elements).
fn push_str_field(record: &mut String, name: &str, value: &str) {
    if !name.is_empty() {
        record.push('"');
        record.push_str(name);
        record.push_str("\":");
    }
    record.push('"');
    for ch in value.chars() {
        match ch {
            '"' => record.push_str("\\\""),
            '\\' => record.push_str("\\\\"),
            _ => record.push(ch),
        }
    }
    record.push('"');
}
