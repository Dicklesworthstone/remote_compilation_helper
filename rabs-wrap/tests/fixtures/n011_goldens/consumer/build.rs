//! N011 golden-consumer build script: records every DEP_* variable it
//! observes (sorted NAME=VALUE lines) into OUT_DIR — the downstream
//! half of the byte-exact replay contract.

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
