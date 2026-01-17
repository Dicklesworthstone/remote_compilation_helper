//! Configuration system for RCH.
//!
//! This module provides comprehensive configuration management including:
//! - Environment variable parsing with type safety
//! - .env file support for development
//! - Configuration profiles (dev/prod/test)
//! - Source tracking for debugging
//! - Validation on startup

pub mod dotenv;
pub mod env;
pub mod profiles;
pub mod source;
pub mod validate;

pub use env::{EnvError, EnvParser};
pub use profiles::Profile;
pub use source::{ConfigSource, ConfigValueSource, Sourced};
pub use validate::{ConfigWarning, Severity, validate_config};
