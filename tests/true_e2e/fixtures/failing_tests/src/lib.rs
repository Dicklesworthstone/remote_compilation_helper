//! RCH E2E Test Fixture - Failing Tests
//!
//! This fixture contains intentionally failing tests to verify
//! that exit code 101 is correctly propagated.

/// A simple function that works correctly.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// A function that returns an incorrect value (for failing test).
pub fn buggy_multiply(a: i32, b: i32) -> i32 {
    // Intentionally buggy: returns wrong result
    a + b // Should be a * b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_passing() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn test_add_another_passing() {
        assert_eq!(add(-1, 1), 0);
    }

    #[test]
    fn test_multiply_intentional_fail() {
        // This test intentionally fails because buggy_multiply is buggy
        assert_eq!(buggy_multiply(3, 4), 12, "This should fail: 3+4=7 != 12");
    }

    #[test]
    fn test_another_intentional_fail() {
        // Another intentionally failing test
        assert!(false, "This test always fails");
    }

    #[test]
    fn test_passing_third() {
        assert_eq!(add(10, 20), 30);
    }
}
