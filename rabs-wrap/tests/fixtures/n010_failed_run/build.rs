//! N010/T034 fixture build script. Phase is selected by N010_PHASE:
//!
//! - `fail`: write TWO partial OUT_DIR files, then exit 3 (the failed
//!   run whose partial state must never be published);
//! - anything else (`fix`): succeed, writing ONLY `gen.rs` — it does
//!   NOT clean the stale partials, mirroring stock accumulation.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    match env::var("N010_PHASE").as_deref() {
        Ok("fail") => {
            fs::write(out.join("partial_one.rs"), "pub fn p1() -> u32 { 1 }\n")
                .unwrap();
            fs::write(out.join("partial_two.dat"), b"partial\n").unwrap();
            eprintln!("n010: failing after partial writes");
            std::process::exit(3);
        }
        _ => {
            fs::write(out.join("gen.rs"), "pub fn g() -> u32 { 2 }\n").unwrap();
            println!("cargo:rerun-if-changed=build.rs");
            println!("cargo:rerun-if-env-changed=N010_PHASE");
        }
    }
}
