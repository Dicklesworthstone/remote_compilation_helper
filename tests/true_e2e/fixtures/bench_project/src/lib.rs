//! RCH E2E Test Fixture - Bench Project
//!
//! Minimal library for cargo bench verification.

/// Add two integers (used by benches).
pub fn add(a: u64, b: u64) -> u64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(1, 2), 3);
    }
}
