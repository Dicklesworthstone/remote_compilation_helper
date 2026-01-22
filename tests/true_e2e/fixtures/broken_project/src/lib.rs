//! RCH E2E Test Fixture - Broken Project
//!
//! This fixture contains intentional compilation errors to verify
//! that exit code 1 is correctly propagated.

/// This function has a compilation error.
pub fn broken_function() -> i32 {
    // Intentional compilation error: missing semicolon and type mismatch
    let x: i32 = "not an integer"  // Type error!
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broken() {
        // This test can't even compile
        let _ = broken_function();
    }
}
