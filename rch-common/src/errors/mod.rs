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
//! | E013-E018  |   PathDeps  |   Path-dependency resolution errors  |
//! | E019-E024  |   Closure   |   Dependency-closure planner errors  |
//! | E100-E199  | Network     | Network and SSH connectivity         |
//! | E200-E299  | Worker      | Worker selection and management      |
//! | E210-E219  |   Storage   |   Disk pressure and storage errors   |
//! | E300-E399  | Build       | Compilation and build errors         |
//! | E310-E319  |   Triage    |   Process triage integration errors  |
//! | E400-E499  | Transfer    | File transfer and sync errors        |
//! | E500-E599  | Internal    | Internal/unexpected errors           |
//!
//! Reliability-doctor reason codes use a separate `RCH-Rnnn` namespace; see
//! [`reliability`] for the full table.

pub mod catalog;
pub mod explain;
pub mod reliability;

pub use catalog::{ErrorCategory, ErrorCode, ErrorEntry};
pub use explain::{
    CodeExplanation, CodeNamespace, is_known, list_all, list_by_category, lookup, render_human,
};
pub use reliability::{ReliabilityCategoryKind, ReliabilityReasonCode};
