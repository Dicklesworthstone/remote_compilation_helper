//! Integration tests for the hello_world fixture.
//!
//! These tests verify that the library functions work correctly
//! when tested as an external crate.

use hello_world::{add, factorial, multiply};

#[test]
fn test_add_from_integration() {
    assert_eq!(add(10, 20), 30);
    assert_eq!(add(-5, 5), 0);
    assert_eq!(add(0, 0), 0);
}

#[test]
fn test_multiply_from_integration() {
    assert_eq!(multiply(7, 8), 56);
    assert_eq!(multiply(-3, 4), -12);
}

#[test]
fn test_factorial_from_integration() {
    assert_eq!(factorial(0), 1);
    assert_eq!(factorial(6), 720);
    assert_eq!(factorial(12), 479001600);
}

#[test]
fn test_combined_operations() {
    // (2 + 3) * 4 = 20
    let sum = add(2, 3);
    let product = multiply(sum, 4);
    assert_eq!(product, 20);
}

#[test]
#[ignore]
fn test_integration_ignored_failure() {
    // This test intentionally fails when run with --ignored
    panic!("Integration test intentional failure");
}
