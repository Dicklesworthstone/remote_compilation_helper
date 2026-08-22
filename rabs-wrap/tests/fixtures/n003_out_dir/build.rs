//! N003 fixture build script: generates an INCLUDED unit plus a
//! side-data file deliberately NOT referenced by the crate — the safe
//! deletion victim (deleting an INCLUDED file breaks later builds).

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Included unit: deleting this would break subsequent builds.
    fs::write(out.join("gen.rs"), "pub fn g() -> u32 { 1 }\n").unwrap();
    // Side data: present in the tree, never referenced by the crate.
    fs::write(out.join("side_data.bin"), b"n003-side-payload\n").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
