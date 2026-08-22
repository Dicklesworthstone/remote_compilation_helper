//! N011 golden-provider build script: emits the COMPLETE directive
//! corpus surface (every registered kind plus an unknown key, chatter,
//! collisions) with deterministic byte output across toolchains.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("gen.rs"), "pub fn g() -> u32 { 7 }\n").unwrap();
    fs::write(out.join("side.dat"), b"golden-side\n").unwrap();

    // Non-directive chatter interleaved (stdout order still governs).
    println!("compiling golden probe");

    // Rerun triggers.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=N011_GOLDEN_VAR");
    println!("cargo:rustc-flags=-L /tmp/n011-golden");
    // Compiler-facing kinds.
    println!("cargo:rustc-env=N011_GOLDEN=1");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-search=native=/tmp/n011-golden");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--golden");

    // Diagnostics.
    println!("cargo:warning=golden warning one");
    println!("cargo:warning=golden warning two");

    // Downstream metadata (collision: second wins).
    println!("cargo:metadata=VERSION=1.0.0-first");
    println!("cargo:metadata=VERSION=1.0.0-final");
    println!("cargo:metadata=FEATURE=enabled");

    // Unknown key (forwarded to dependents, bytes preserved).
    println!("cargo:future_thing=fv1");

    // Legacy kind.
    println!("cargo:dep-info=extra.d");

    // Chatter tail.
    eprintln!("golden stderr line");
}
