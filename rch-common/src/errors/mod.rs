//! Error catalog and definitions for Remote Compilation Helper
//!
//! This module provides a comprehensive error catalog with unique error codes,
//! categorized by subsystem. Each error includes remediation steps and
//! documentation links.
//!
//! # Error Code Ranges
//!
//! | Range      | Category    | Description                          |
//! |------------|-------------|--------------------------------------|
//! | E001-E099  | Config      | Configuration and setup errors       |
//! | E100-E199  | Network     | Network and SSH connectivity         |
//! | E200-E299  | Worker      | Worker selection and management      |
//! | E300-E399  | Build       | Compilation and build errors         |
//! | E400-E499  | Transfer    | File transfer and sync errors        |
//! | E500-E599  | Internal    | Internal/unexpected errors           |

pub mod catalog;

pub use catalog::{ErrorCategory, ErrorCode, ErrorEntry};
