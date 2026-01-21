//! RCH E2E Test Fixture - Hello World Binary
//!
//! This simple binary is used to test that remote compilation produces
//! the same output as local compilation.

use hello_world::add;

fn main() {
    println!("Hello from rch test fixture!");
    println!("2 + 2 = {}", add(2, 2));
}
