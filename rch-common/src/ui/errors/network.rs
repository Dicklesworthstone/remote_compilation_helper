//! NetworkErrorDisplay - Specialized display for network and SSH errors.
//!
//! This module provides rich error display for network connectivity issues,
//! including SSH failures, DNS errors, timeouts, and authentication problems.
//!
//! # Features
//!
//! - Parses `std::io::Error` and `ssh2` errors for detail extraction
//! - Displays network path visualization (local → daemon → worker)
//! - Shows relevant environment variables (SSH_AUTH_SOCK, etc.)
//! - Suggests diagnostic commands (ping, nc, ssh -vvv)
//! - Supports JSON serialization for structured output
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::errors::NetworkErrorDisplay;
//! use rch_common::ui::OutputContext;
//!
//! let display = NetworkErrorDisplay::ssh_connection_failed("build1.internal")
//!     .port(22)
//!     .timeout_secs(30)
//!     .with_io_error(&io_err)
//!     .network_path("local", "daemon", "worker");
//!
//! display.render(OutputContext::detect());
//! ```

use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crate::errors::catalog::ErrorCode;
use crate::ui::{ErrorPanel, Icons, OutputContext, RchTheme};

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::HEAVY;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

/// Network connection details for error display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDetails {
    /// Hostname or address attempted
    pub host: String,
    /// Port number (default 22 for SSH)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Resolved IP address if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<IpAddr>,
    /// SSH username if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// SSH key path if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

/// Network path segment for visualizing connection flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPathSegment {
    /// Segment name (e.g., "local", "daemon", "worker")
    pub name: String,
    /// Segment status
    pub status: PathSegmentStatus,
    /// Optional details about this segment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Status of a network path segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathSegmentStatus {
    /// Segment is working
    Ok,
    /// Segment failed
    Failed,
    /// Segment status unknown
    Unknown,
}

/// Environment variable relevant to network errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarInfo {
    /// Variable name
    pub name: String,
    /// Variable value (redacted if sensitive)
    pub value: Option<String>,
    /// Whether value is set
    pub is_set: bool,
}

/// Diagnostic command suggestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCommand {
    /// Brief description of what the command checks
    pub description: String,
    /// The command to run
    pub command: String,
}

/// NetworkErrorDisplay - Rich error display for network/SSH errors.
///
/// Builds on [`ErrorPanel`] with network-specific context:
/// - Connection details (host, port, IP, credentials)
/// - Network path visualization
/// - Environment variable display
/// - Diagnostic command suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkErrorDisplay {
    /// The underlying error code
    pub error_code: ErrorCode,

    /// Connection details
    pub connection: ConnectionDetails,

    /// Network path segments for visualization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_path: Vec<NetworkPathSegment>,

    /// Relevant environment variables
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_vars: Vec<EnvVarInfo>,

    /// Diagnostic command suggestions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<DiagnosticCommand>,

    /// Connection timeout if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,

    /// Retry information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,

    /// Low-level error message from OS/library
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_error: Option<String>,

    /// Error chain (caused by)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<String>,

    /// Custom message override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_message: Option<String>,
}

impl NetworkErrorDisplay {
    // ========================================================================
    // CONSTRUCTORS FOR SPECIFIC ERROR TYPES
    // ========================================================================

    /// Create display for SSH connection failure (E100).
    #[must_use]
    pub fn ssh_connection_failed(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshConnectionFailed, host.clone())
            .add_diagnostic("Test basic connectivity", format!("ping -c 3 {host}"))
            .add_diagnostic("Check SSH port", format!("nc -zv {host} 22"))
            .add_diagnostic("Verbose SSH connection", format!("ssh -vvv {host}"))
    }

    /// Create display for SSH authentication failure (E101).
    #[must_use]
    pub fn ssh_auth_failed(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshAuthFailed, host.clone())
            .auto_add_ssh_env_vars()
            .add_diagnostic("List loaded SSH keys", "ssh-add -l".to_string())
            .add_diagnostic(
                "Check authorized_keys",
                format!("ssh {host} 'cat ~/.ssh/authorized_keys'"),
            )
            .add_diagnostic("Verbose SSH auth", format!("ssh -vvv {host}"))
    }

    /// Create display for SSH key error (E102).
    #[must_use]
    pub fn ssh_key_error(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshKeyError, host)
            .auto_add_ssh_env_vars()
            .add_diagnostic("List SSH keys", "ls -la ~/.ssh/".to_string())
            .add_diagnostic(
                "Check key format",
                "ssh-keygen -y -f ~/.ssh/id_ed25519".to_string(),
            )
            .add_diagnostic("List loaded keys", "ssh-add -l".to_string())
    }

    /// Create display for SSH host key verification failure (E103).
    #[must_use]
    pub fn ssh_host_key_error(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshHostKeyError, host.clone())
            .add_diagnostic("View known_hosts entry", format!("ssh-keygen -F {host}"))
            .add_diagnostic("Remove old host key", format!("ssh-keygen -R {host}"))
            .add_diagnostic("Show host fingerprint", format!("ssh-keyscan {host}"))
    }

    /// Create display for SSH timeout (E104).
    #[must_use]
    pub fn ssh_timeout(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshTimeout, host.clone())
            .add_diagnostic("Test connectivity", format!("ping -c 3 {host}"))
            .add_diagnostic("Check route", format!("traceroute {host}"))
            .add_diagnostic(
                "Test SSH with timeout",
                format!("timeout 10 ssh -v {host} exit"),
            )
    }

    /// Create display for SSH session dropped (E105).
    #[must_use]
    pub fn ssh_session_dropped(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::SshSessionDropped, host.clone())
            .add_diagnostic("Check host uptime", format!("ssh {host} uptime"))
            .add_diagnostic(
                "Test connection stability",
                format!("ssh {host} 'sleep 5 && echo ok'"),
            )
    }

    /// Create display for DNS resolution failure (E106).
    #[must_use]
    pub fn dns_error(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::NetworkDnsError, host.clone())
            .add_diagnostic("DNS lookup", format!("nslookup {host}"))
            .add_diagnostic("Alternative DNS lookup", format!("dig {host}"))
            .add_diagnostic("Check /etc/hosts", format!("grep {host} /etc/hosts"))
    }

    /// Create display for network unreachable (E107).
    #[must_use]
    pub fn network_unreachable(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::NetworkUnreachable, host.clone())
            .add_diagnostic("Check network interface", "ip addr show".to_string())
            .add_diagnostic("Check routing table", "ip route show".to_string())
            .add_diagnostic("Trace route", format!("traceroute {host}"))
    }

    /// Create display for connection refused (E108).
    #[must_use]
    pub fn connection_refused(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::NetworkConnectionRefused, host.clone())
            .add_diagnostic(
                "Check if SSH is running",
                format!("ssh {host} 'systemctl status sshd'"),
            )
            .add_diagnostic("Check port", format!("nc -zv {host} 22"))
            .add_diagnostic(
                "Check firewall (remote)",
                format!("ssh {host} 'iptables -L -n'"),
            )
    }

    /// Create display for TCP timeout (E109).
    #[must_use]
    pub fn tcp_timeout(host: impl Into<String>) -> Self {
        let host = host.into();
        Self::new(ErrorCode::NetworkTimeout, host.clone())
            .add_diagnostic("Check latency", format!("ping -c 5 {host}"))
            .add_diagnostic("Check route", format!("traceroute {host}"))
            .add_diagnostic(
                "Test port with timeout",
                format!("timeout 5 nc -zv {host} 22"),
            )
    }

    // ========================================================================
    // CORE CONSTRUCTOR
    // ========================================================================

    /// Create a new NetworkErrorDisplay with error code and host.
    #[must_use]
    fn new(error_code: ErrorCode, host: impl Into<String>) -> Self {
        Self {
            error_code,
            connection: ConnectionDetails {
                host: host.into(),
                port: None,
                resolved_ip: None,
                username: None,
                key_path: None,
            },
            network_path: Vec::new(),
            env_vars: Vec::new(),
            diagnostics: Vec::new(),
            timeout: None,
            retry_count: None,
            raw_error: None,
            caused_by: Vec::new(),
            custom_message: None,
        }
    }

    // ========================================================================
    // BUILDER METHODS - CONNECTION DETAILS
    // ========================================================================

    /// Set the port number.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.connection.port = Some(port);
        self
    }

    /// Set the resolved IP address.
    #[must_use]
    pub fn resolved_ip(mut self, ip: IpAddr) -> Self {
        self.connection.resolved_ip = Some(ip);
        self
    }

    /// Set the SSH username.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.connection.username = Some(username.into());
        self
    }

    /// Set the SSH key path.
    #[must_use]
    pub fn key_path(mut self, path: impl Into<String>) -> Self {
        self.connection.key_path = Some(path.into());
        self
    }

    // ========================================================================
    // BUILDER METHODS - TIMEOUT AND RETRY
    // ========================================================================

    /// Set the timeout duration.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the timeout in seconds (convenience method).
    #[must_use]
    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    /// Set the retry count.
    #[must_use]
    pub fn retries(mut self, count: u32) -> Self {
        self.retry_count = Some(count);
        self
    }

    // ========================================================================
    // BUILDER METHODS - NETWORK PATH
    // ========================================================================

    /// Add a network path segment.
    #[must_use]
    pub fn path_segment(
        mut self,
        name: impl Into<String>,
        status: PathSegmentStatus,
        details: Option<String>,
    ) -> Self {
        self.network_path.push(NetworkPathSegment {
            name: name.into(),
            status,
            details,
        });
        self
    }

    /// Set the full network path with simple status.
    ///
    /// Creates a path like: local → daemon → worker
    /// The failed segment is marked based on which name matches `failed_at`.
    #[must_use]
    pub fn network_path_simple(
        self,
        local: &str,
        daemon: &str,
        worker: &str,
        failed_at: Option<&str>,
    ) -> Self {
        let status_for = |name: &str| {
            if Some(name) == failed_at {
                PathSegmentStatus::Failed
            } else if failed_at.is_some() {
                // If something failed, segments before it are OK, after are unknown
                PathSegmentStatus::Unknown
            } else {
                PathSegmentStatus::Ok
            }
        };

        self.path_segment(local, status_for(local), None)
            .path_segment(daemon, status_for(daemon), None)
            .path_segment(worker, status_for(worker), None)
    }

    // ========================================================================
    // BUILDER METHODS - ENVIRONMENT VARIABLES
    // ========================================================================

    /// Add an environment variable with its current value.
    #[must_use]
    pub fn env_var(mut self, name: impl Into<String>, value: Option<String>) -> Self {
        let name = name.into();
        self.env_vars.push(EnvVarInfo {
            name,
            is_set: value.is_some(),
            value,
        });
        self
    }

    /// Add an environment variable, reading from the current environment.
    #[must_use]
    pub fn env_var_from_env(self, name: &str) -> Self {
        let value = std::env::var(name).ok();
        self.env_var(name, value)
    }

    /// Automatically add common SSH-related environment variables.
    #[must_use]
    pub fn auto_add_ssh_env_vars(self) -> Self {
        self.env_var_from_env("SSH_AUTH_SOCK")
            .env_var_from_env("SSH_AGENT_PID")
            .env_var_from_env("HOME")
    }

    // ========================================================================
    // BUILDER METHODS - DIAGNOSTICS
    // ========================================================================

    /// Add a diagnostic command suggestion.
    #[must_use]
    pub fn add_diagnostic(
        mut self,
        description: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        self.diagnostics.push(DiagnosticCommand {
            description: description.into(),
            command: command.into(),
        });
        self
    }

    // ========================================================================
    // BUILDER METHODS - ERROR PARSING
    // ========================================================================

    /// Extract details from a std::io::Error.
    #[must_use]
    pub fn with_io_error(mut self, err: &io::Error) -> Self {
        self.raw_error = Some(err.to_string());

        // Extract OS error code if available
        if let Some(os_err) = err.raw_os_error() {
            self.caused_by.push(format!("OS error {}: {}", os_err, err));
        }

        // Detect specific error kinds
        match err.kind() {
            io::ErrorKind::ConnectionRefused => {
                self.caused_by
                    .push("Connection actively refused by remote host".to_string());
            }
            io::ErrorKind::ConnectionReset => {
                self.caused_by
                    .push("Connection was reset by remote host".to_string());
            }
            io::ErrorKind::ConnectionAborted => {
                self.caused_by.push("Connection was aborted".to_string());
            }
            io::ErrorKind::NotConnected => {
                self.caused_by.push("Socket is not connected".to_string());
            }
            io::ErrorKind::TimedOut => {
                self.caused_by.push("Operation timed out".to_string());
            }
            io::ErrorKind::HostUnreachable => {
                self.caused_by.push("Host is unreachable".to_string());
            }
            io::ErrorKind::NetworkUnreachable => {
                self.caused_by.push("Network is unreachable".to_string());
            }
            _ => {}
        }

        self
    }

    /// Set a custom error message.
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.custom_message = Some(message.into());
        self
    }

    /// Add a caused-by entry.
    #[must_use]
    pub fn caused_by(mut self, cause: impl Into<String>) -> Self {
        self.caused_by.push(cause.into());
        self
    }

    // ========================================================================
    // CONVERSION TO ErrorPanel
    // ========================================================================

    /// Convert to an ErrorPanel for rendering.
    #[must_use]
    pub fn to_error_panel(&self) -> ErrorPanel {
        let entry = self.error_code.entry();

        let mut panel = ErrorPanel::error(&entry.code, &entry.message);

        // Set custom message if provided
        if let Some(ref msg) = self.custom_message {
            panel = panel.message(msg.clone());
        } else if let Some(ref raw) = self.raw_error {
            panel = panel.message(raw.clone());
        }

        // Add connection details as context
        panel = panel.context("Host", &self.connection.host);
        if let Some(port) = self.connection.port {
            panel = panel.context("Port", port.to_string());
        }
        if let Some(ref ip) = self.connection.resolved_ip {
            panel = panel.context("Resolved IP", ip.to_string());
        }
        if let Some(ref user) = self.connection.username {
            panel = panel.context("Username", user.clone());
        }
        if let Some(ref key) = self.connection.key_path {
            panel = panel.context("SSH Key", key.clone());
        }

        // Add timeout and retry info
        if let Some(ref timeout) = self.timeout {
            panel = panel.context("Timeout", format!("{:.1}s", timeout.as_secs_f64()));
        }
        if let Some(retries) = self.retry_count {
            panel = panel.context("Retries", retries.to_string());
        }

        // Add caused-by chain
        for cause in &self.caused_by {
            panel = panel.caused_by(cause.clone(), None);
        }

        // Add remediation from catalog
        for step in entry.remediation {
            panel = panel.suggestion(step);
        }

        panel
    }

    // ========================================================================
    // RENDERING
    // ========================================================================

    /// Render the error to stderr.
    ///
    /// Uses rich output if supported, otherwise plain text.
    pub fn render(&self, ctx: OutputContext) {
        if ctx.is_machine() {
            // Machine mode - caller should use to_json()
            return;
        }

        #[cfg(feature = "rich-ui")]
        if ctx.supports_rich() {
            self.render_rich(ctx);
            return;
        }

        self.render_plain(ctx);
    }

    /// Render using rich_rust Panel with network-specific formatting.
    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, ctx: OutputContext) {
        let content = self.build_rich_content(ctx);
        let entry = self.error_code.entry();
        let icon = Icons::cross(ctx);
        let title_text = format!("{icon} {}: {}", entry.code, entry.message);

        let border_color = Color::parse(RchTheme::ERROR).unwrap_or_else(|_| Color::default());
        let border_style = Style::new().bold().color(border_color);

        let panel = Panel::from_text(&content)
            .title(title_text.as_str())
            .border_style(border_style)
            .box_style(&HEAVY);

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    /// Build rich content string.
    #[cfg(feature = "rich-ui")]
    fn build_rich_content(&self, ctx: OutputContext) -> String {
        let mut lines = Vec::new();

        // Custom or raw error message
        if let Some(ref msg) = self.custom_message {
            lines.push(msg.clone());
        } else if let Some(ref raw) = self.raw_error {
            lines.push(raw.clone());
        }

        // Connection details
        lines.push(String::new());
        lines.push(format!("[{}]Connection:[/]", RchTheme::DIM));
        lines.push(format!("  Host: {}", self.connection.host));
        if let Some(port) = self.connection.port {
            lines.push(format!("  Port: {port}"));
        }
        if let Some(ref ip) = self.connection.resolved_ip {
            lines.push(format!("  Resolved IP: {ip}"));
        }
        if let Some(ref user) = self.connection.username {
            lines.push(format!("  Username: {user}"));
        }
        if let Some(ref key) = self.connection.key_path {
            lines.push(format!("  SSH Key: {key}"));
        }
        if let Some(ref timeout) = self.timeout {
            lines.push(format!("  Timeout: {:.1}s", timeout.as_secs_f64()));
        }
        if let Some(retries) = self.retry_count {
            lines.push(format!("  Retries: {retries}"));
        }

        // Network path visualization
        if !self.network_path.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Network Path:[/]", RchTheme::DIM));
            lines.push(format!("  {}", self.format_network_path(ctx)));
        }

        // Environment variables
        if !self.env_vars.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Environment:[/]", RchTheme::DIM));
            for var in &self.env_vars {
                let value = if var.is_set {
                    var.value.as_deref().unwrap_or("(set)")
                } else {
                    "(not set)"
                };
                lines.push(format!("  {}: {}", var.name, value));
            }
        }

        // Error chain
        if !self.caused_by.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Caused by:[/]", RchTheme::DIM));
            for cause in &self.caused_by {
                lines.push(format!("  {cause}"));
            }
        }

        // Diagnostic commands
        if !self.diagnostics.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Diagnostic Commands:[/]", RchTheme::SECONDARY));
            for (i, diag) in self.diagnostics.iter().enumerate() {
                lines.push(format!(
                    "  [{}]{}.[/] {} [{}]{}[/]",
                    RchTheme::SECONDARY,
                    i + 1,
                    diag.description,
                    RchTheme::DIM,
                    diag.command
                ));
            }
        }

        // Remediation from catalog
        let entry = self.error_code.entry();
        if !entry.remediation.is_empty() {
            lines.push(String::new());
            lines.push(format!("[{}]Suggestions:[/]", RchTheme::SECONDARY));
            for (i, step) in entry.remediation.iter().enumerate() {
                lines.push(format!("  [{}]{}.[/] {step}", RchTheme::SECONDARY, i + 1));
            }
        }

        lines.join("\n")
    }

    /// Render plain text to stderr.
    fn render_plain(&self, ctx: OutputContext) {
        let entry = self.error_code.entry();
        let icon = Icons::cross(ctx);

        // Header line
        eprintln!("{icon} [ERROR] {}: {}", entry.code, entry.message);

        // Custom or raw error message
        if let Some(ref msg) = self.custom_message {
            eprintln!();
            eprintln!("{msg}");
        } else if let Some(ref raw) = self.raw_error {
            eprintln!();
            eprintln!("{raw}");
        }

        // Connection details
        eprintln!();
        eprintln!("Connection:");
        eprintln!("  Host: {}", self.connection.host);
        if let Some(port) = self.connection.port {
            eprintln!("  Port: {port}");
        }
        if let Some(ref ip) = self.connection.resolved_ip {
            eprintln!("  Resolved IP: {ip}");
        }
        if let Some(ref user) = self.connection.username {
            eprintln!("  Username: {user}");
        }
        if let Some(ref key) = self.connection.key_path {
            eprintln!("  SSH Key: {key}");
        }
        if let Some(ref timeout) = self.timeout {
            eprintln!("  Timeout: {:.1}s", timeout.as_secs_f64());
        }
        if let Some(retries) = self.retry_count {
            eprintln!("  Retries: {retries}");
        }

        // Network path visualization
        if !self.network_path.is_empty() {
            eprintln!();
            eprintln!("Network Path:");
            eprintln!("  {}", self.format_network_path(ctx));
        }

        // Environment variables
        if !self.env_vars.is_empty() {
            eprintln!();
            eprintln!("Environment:");
            for var in &self.env_vars {
                let value = if var.is_set {
                    var.value.as_deref().unwrap_or("(set)")
                } else {
                    "(not set)"
                };
                eprintln!("  {}: {}", var.name, value);
            }
        }

        // Error chain
        if !self.caused_by.is_empty() {
            eprintln!();
            eprintln!("Caused by:");
            for cause in &self.caused_by {
                eprintln!("  {cause}");
            }
        }

        // Diagnostic commands
        if !self.diagnostics.is_empty() {
            eprintln!();
            eprintln!("Diagnostic Commands:");
            for (i, diag) in self.diagnostics.iter().enumerate() {
                eprintln!("  {}. {}: {}", i + 1, diag.description, diag.command);
            }
        }

        // Remediation from catalog
        if !entry.remediation.is_empty() {
            eprintln!();
            eprintln!("Suggestions:");
            for (i, step) in entry.remediation.iter().enumerate() {
                eprintln!("  {}. {step}", i + 1);
            }
        }
    }

    /// Format the network path for display.
    fn format_network_path(&self, ctx: OutputContext) -> String {
        let arrow = if ctx.supports_unicode() {
            " → "
        } else {
            " -> "
        };
        let check = Icons::check(ctx);
        let cross = Icons::cross(ctx);
        let question = if ctx.supports_unicode() { "?" } else { "?" };

        self.network_path
            .iter()
            .map(|seg| {
                let icon = match seg.status {
                    PathSegmentStatus::Ok => check,
                    PathSegmentStatus::Failed => cross,
                    PathSegmentStatus::Unknown => question,
                };
                format!("{icon}{}", seg.name)
            })
            .collect::<Vec<_>>()
            .join(arrow)
    }

    // ========================================================================
    // JSON SERIALIZATION
    // ========================================================================

    /// Serialize to JSON string.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON string.
    pub fn to_json_compact(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl std::fmt::Display for NetworkErrorDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry = self.error_code.entry();
        write!(f, "[ERROR] {}: {}", entry.code, entry.message)?;
        if let Some(ref msg) = self.custom_message {
            write!(f, " - {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NetworkErrorDisplay {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_connection_failed_creation() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1.internal");
        assert_eq!(display.error_code, ErrorCode::SshConnectionFailed);
        assert_eq!(display.connection.host, "build1.internal");
        assert!(!display.diagnostics.is_empty());
    }

    #[test]
    fn test_ssh_auth_failed_creation() {
        let display = NetworkErrorDisplay::ssh_auth_failed("build1.internal");
        assert_eq!(display.error_code, ErrorCode::SshAuthFailed);
        assert!(!display.env_vars.is_empty()); // auto-added SSH env vars
    }

    #[test]
    fn test_builder_chain() {
        let display = NetworkErrorDisplay::ssh_connection_failed("example.com")
            .port(2222)
            .username("deploy")
            .timeout_secs(30)
            .retries(3);

        assert_eq!(display.connection.port, Some(2222));
        assert_eq!(display.connection.username, Some("deploy".to_string()));
        assert_eq!(display.timeout, Some(Duration::from_secs(30)));
        assert_eq!(display.retry_count, Some(3));
    }

    #[test]
    fn test_resolved_ip() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let display = NetworkErrorDisplay::ssh_connection_failed("build1").resolved_ip(ip);

        assert_eq!(display.connection.resolved_ip, Some(ip));
    }

    #[test]
    fn test_network_path() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1").network_path_simple(
            "local",
            "daemon",
            "worker",
            Some("worker"),
        );

        assert_eq!(display.network_path.len(), 3);
        assert_eq!(display.network_path[2].status, PathSegmentStatus::Failed);
    }

    #[test]
    fn test_with_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused");
        let display = NetworkErrorDisplay::ssh_connection_failed("build1").with_io_error(&io_err);

        assert!(display.raw_error.is_some());
        assert!(!display.caused_by.is_empty());
    }

    #[test]
    fn test_env_var() {
        let display = NetworkErrorDisplay::ssh_auth_failed("build1")
            .env_var("TEST_VAR", Some("test_value".to_string()));

        let test_var = display.env_vars.iter().find(|v| v.name == "TEST_VAR");
        assert!(test_var.is_some());
        assert_eq!(test_var.unwrap().value, Some("test_value".to_string()));
    }

    #[test]
    fn test_diagnostic_commands() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .add_diagnostic("Custom check", "custom-cmd");

        assert!(
            display
                .diagnostics
                .iter()
                .any(|d| d.command == "custom-cmd")
        );
    }

    #[test]
    fn test_to_error_panel() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .port(22)
            .message("Custom message");

        let panel = display.to_error_panel();
        assert_eq!(panel.code, "RCH-E100");
        assert!(panel.message.is_some());
    }

    #[test]
    fn test_json_serialization() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .port(22)
            .username("deploy");

        let json = display.to_json().expect("JSON serialization failed");
        assert!(json.contains("build1"));
        assert!(json.contains("22"));
        assert!(json.contains("deploy"));
    }

    #[test]
    fn test_json_compact_serialization() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1");
        let json = display
            .to_json_compact()
            .expect("JSON serialization failed");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_display_implementation() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1").message("Test message");

        let output = format!("{display}");
        assert!(output.contains("RCH-E100"));
        assert!(output.contains("Test message"));
    }

    #[test]
    fn test_render_plain_no_panic() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .port(22)
            .username("deploy")
            .network_path_simple("local", "daemon", "worker", Some("worker"))
            .env_var("SSH_AUTH_SOCK", Some("/tmp/ssh-agent.sock".to_string()))
            .message("Connection failed");

        // Should not panic
        display.render(OutputContext::Plain);
    }

    #[test]
    fn test_render_machine_silent() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1");
        // Should not output anything in machine mode
        display.render(OutputContext::Machine);
    }

    #[test]
    fn test_all_error_constructors() {
        // Verify all constructors work and set correct error codes
        assert_eq!(
            NetworkErrorDisplay::ssh_connection_failed("h").error_code,
            ErrorCode::SshConnectionFailed
        );
        assert_eq!(
            NetworkErrorDisplay::ssh_auth_failed("h").error_code,
            ErrorCode::SshAuthFailed
        );
        assert_eq!(
            NetworkErrorDisplay::ssh_key_error("h").error_code,
            ErrorCode::SshKeyError
        );
        assert_eq!(
            NetworkErrorDisplay::ssh_host_key_error("h").error_code,
            ErrorCode::SshHostKeyError
        );
        assert_eq!(
            NetworkErrorDisplay::ssh_timeout("h").error_code,
            ErrorCode::SshTimeout
        );
        assert_eq!(
            NetworkErrorDisplay::ssh_session_dropped("h").error_code,
            ErrorCode::SshSessionDropped
        );
        assert_eq!(
            NetworkErrorDisplay::dns_error("h").error_code,
            ErrorCode::NetworkDnsError
        );
        assert_eq!(
            NetworkErrorDisplay::network_unreachable("h").error_code,
            ErrorCode::NetworkUnreachable
        );
        assert_eq!(
            NetworkErrorDisplay::connection_refused("h").error_code,
            ErrorCode::NetworkConnectionRefused
        );
        assert_eq!(
            NetworkErrorDisplay::tcp_timeout("h").error_code,
            ErrorCode::NetworkTimeout
        );
    }

    #[test]
    fn test_format_network_path() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .path_segment("local", PathSegmentStatus::Ok, None)
            .path_segment("daemon", PathSegmentStatus::Ok, None)
            .path_segment("worker", PathSegmentStatus::Failed, None);

        let path = display.format_network_path(OutputContext::Plain);
        assert!(path.contains("local"));
        assert!(path.contains("daemon"));
        assert!(path.contains("worker"));
    }

    #[test]
    fn test_path_segment_status() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1").path_segment(
            "seg1",
            PathSegmentStatus::Ok,
            Some("details".to_string()),
        );

        assert_eq!(display.network_path.len(), 1);
        assert_eq!(display.network_path[0].status, PathSegmentStatus::Ok);
        assert_eq!(display.network_path[0].details, Some("details".to_string()));
    }

    #[test]
    fn test_key_path() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .key_path("/home/user/.ssh/id_ed25519");

        assert_eq!(
            display.connection.key_path,
            Some("/home/user/.ssh/id_ed25519".to_string())
        );
    }

    #[test]
    fn test_caused_by_chain() {
        let display = NetworkErrorDisplay::ssh_connection_failed("build1")
            .caused_by("First cause")
            .caused_by("Second cause");

        assert_eq!(display.caused_by.len(), 2);
        assert_eq!(display.caused_by[0], "First cause");
        assert_eq!(display.caused_by[1], "Second cause");
    }

    #[test]
    fn test_error_trait() {
        let display: Box<dyn std::error::Error> =
            Box::new(NetworkErrorDisplay::ssh_connection_failed("build1"));
        let _ = format!("{display}");
    }
}
