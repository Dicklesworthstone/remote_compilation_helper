//! Specialized error display components for RCH.
//!
//! This module provides error display components specialized for different
//! error categories. Each component builds on [`ErrorPanel`] but adds
//! domain-specific context extraction and formatting.
//!
//! # Components
//!
//! - [`NetworkErrorDisplay`]: SSH and network connectivity errors
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::errors::NetworkErrorDisplay;
//! use rch_common::ui::OutputContext;
//!
//! let display = NetworkErrorDisplay::ssh_connection_failed("build1.internal")
//!     .port(22)
//!     .with_io_error(&io_err)
//!     .network_path("local", "daemon", "worker")
//!     .env_var("SSH_AUTH_SOCK", std::env::var("SSH_AUTH_SOCK").ok());
//!
//! display.render(OutputContext::detect());
//! ```

pub mod network;

pub use network::NetworkErrorDisplay;
