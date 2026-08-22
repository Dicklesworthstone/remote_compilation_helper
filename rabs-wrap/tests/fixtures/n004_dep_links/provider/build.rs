//! N004 provider build script: emits directives spanning the measured
//! forwarding partition (metadata + unknown keys forward; consumed
//! kinds do not) plus collision and interior-'=' cases.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("gen.rs"), "pub fn g() -> u32 { 1 }\n").unwrap();

    // Forwarded set (measured): metadata + unknown keys.
    println!("cargo:PlainKey=plain-value");
    println!("cargo:lower_case=lw");
    println!("cargo:Mixed==equals==inside");
    println!("cargo:hyphen-key=hv");
    println!("cargo:metadata=first");
    println!("cargo:metadata=second");
    println!("cargo:metadata=DEP_X=y");

    // Consumed set (measured): never reaches dependents.
    println!("cargo:rustc-env=RUSTC_ENV_VAR=rv");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:warning=a-warning");
    println!("cargo:rustc-link-search=native=/tmp");
}
