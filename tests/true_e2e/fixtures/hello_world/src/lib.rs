//! RCH E2E Test Fixture - Hello World Library
//!
//! This library provides simple functions used for testing.

/// Add two integers together.
///
/// # Examples
///
/// ```
/// assert_eq!(hello_world::add(2, 2), 4);
/// ```
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// Multiply two integers together.
pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

/// Compute the factorial of a non-negative integer.
///
/// # Panics
///
/// Panics if n is negative (but i32 is used for testing purposes).
pub fn factorial(n: u32) -> u64 {
    match n {
        0 | 1 => 1,
        _ => n as u64 * factorial(n - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_works() {
        assert_eq!(add(2, 2), 4);
    }

    #[test]
    fn test_add_negative() {
        assert_eq!(add(-1, 1), 0);
    }

    #[test]
    fn test_multiply_works() {
        assert_eq!(multiply(3, 4), 12);
    }

    #[test]
    fn test_multiply_by_zero() {
        assert_eq!(multiply(5, 0), 0);
    }

    #[test]
    fn test_factorial_base_cases() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
    }

    #[test]
    fn test_factorial_recursive() {
        assert_eq!(factorial(5), 120);
        assert_eq!(factorial(10), 3628800);
    }

    #[test]
    #[ignore]
    fn test_ignored_failure() {
        // This test intentionally fails when run with --ignored
        // Used to verify that test failure handling works correctly
        panic!("This test intentionally fails when run with --ignored");
    }

    #[test]
    #[ignore]
    fn test_ignored_slow_computation() {
        // This test is ignored because it takes a long time
        // Used to test that ignored tests can be selectively run
        let result = factorial(20);
        assert_eq!(result, 2432902008176640000);
    }
}
