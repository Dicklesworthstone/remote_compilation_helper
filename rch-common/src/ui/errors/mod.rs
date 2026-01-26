//! Specialized error display components for RCH.
//!
//! This module provides error display components specialized for different
//! error categories. Each component builds on [`super::ErrorPanel`] but adds
//! domain-specific context extraction and formatting.
//!
//! # Components
//!
//! - [`NetworkErrorDisplay`]: SSH and network connectivity errors
//! - [`BuildErrorDisplay`]: Compilation and build errors
//! - [`ConfigErrorDisplay`]: Configuration file and environment errors
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::errors::{NetworkErrorDisplay, BuildErrorDisplay, ConfigErrorDisplay};
//! use rch_common::ui::OutputContext;
//!
//! // Network error
//! let display = NetworkErrorDisplay::ssh_connection_failed("build1.internal")
//!     .port(22)
//!     .with_io_error(&io_err)
//!     .network_path("local", "daemon", "worker")
//!     .env_var("SSH_AUTH_SOCK", std::env::var("SSH_AUTH_SOCK").ok());
//!
//! display.render(OutputContext::detect());
//!
//! // Build error
//! let display = BuildErrorDisplay::build_timeout("cargo build --release")
//!     .worker("build1")
//!     .duration_secs(300)
//!     .timeout_secs(300)
//!     .cpu_usage(98.0)
//!     .memory_usage(14.2, 16.0);
//!
//! display.render(OutputContext::detect());
//!
//! // Config error
//! let display = ConfigErrorDisplay::parse_error("/home/user/.config/rch/config.toml")
//!     .line(13)
//!     .column(15)
//!     .snippet("timeout = \"thirty\"")
//!     .expected("integer")
//!     .actual("string");
//!
//! display.render(OutputContext::detect());
//! ```

pub mod build;
pub mod config;
pub mod network;

pub use build::{BuildErrorDisplay, SignalInfo, WorkerResourceState};
pub use config::{
    ConfigErrorDisplay, ConfigLocation, ConfigSearchPaths, ConfigSnippet, TypeMismatch,
};
pub use network::NetworkErrorDisplay;
