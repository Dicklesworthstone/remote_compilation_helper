//! N004 consumer build script: records EVERY DEP_* variable it observes
//! into OUT_DIR, sorted, `NAME=VALUE` lines — the stock ground truth
//! the replay reconstruction must match exactly.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut lines: Vec<String> = Vec::new();
    for (k, v) in env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("DEP_") {
            lines.push(format!("{}={}", k, v.to_string_lossy()));
        }
    }
    lines.sort();
    fs::write(out.join("dep_observed.txt"), lines.join("\n")).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
