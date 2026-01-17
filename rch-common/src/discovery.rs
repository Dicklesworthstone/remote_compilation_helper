//! Worker discovery from SSH config and shell aliases.
//!
//! This module provides functionality to automatically discover potential
//! worker machines from the user's existing SSH configuration and shell aliases.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A host discovered from SSH config or shell aliases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    /// The alias or short name (e.g., "css", "worker1")
    pub alias: String,
    /// The actual hostname or IP address
    pub hostname: String,
    /// SSH username
    pub user: String,
    /// Path to SSH identity file (private key)
    pub identity_file: Option<String>,
    /// SSH port (default 22)
    pub port: u16,
    /// Where this host was discovered from
    pub source: DiscoverySource,
}

/// Source of a discovered host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// From ~/.ssh/config
    SshConfig,
    /// From ~/.bashrc
    Bashrc,
    /// From ~/.zshrc
    Zshrc,
    /// From ~/.bash_aliases
    BashAliases,
    /// From ~/.zsh_aliases
    ZshAliases,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SshConfig => write!(f, "~/.ssh/config"),
            Self::Bashrc => write!(f, "~/.bashrc"),
            Self::Zshrc => write!(f, "~/.zshrc"),
            Self::BashAliases => write!(f, "~/.bash_aliases"),
            Self::ZshAliases => write!(f, "~/.zsh_aliases"),
        }
    }
}

/// Parse ~/.ssh/config and extract potential worker hosts.
///
/// SSH config format:
/// ```text
/// Host fmd
///     HostName 51.222.245.56
///     User ubuntu
///     IdentityFile ~/.ssh/my_key.pem
///
/// Host yto
///     HostName 37.187.75.150
///     User ubuntu
///     IdentityFile ~/.ssh/my_key.pem
/// ```
///
/// # Returns
/// A list of discovered hosts. Returns empty vec if config doesn't exist.
pub fn parse_ssh_config() -> Result<Vec<DiscoveredHost>> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let ssh_config_path = home.join(".ssh").join("config");

    if !ssh_config_path.exists() {
        return Ok(vec![]);
    }

    parse_ssh_config_file(&ssh_config_path)
}

/// Parse an SSH config file at the given path.
pub fn parse_ssh_config_file(path: &PathBuf) -> Result<Vec<DiscoveredHost>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read SSH config: {}", path.display()))?;

    parse_ssh_config_content(&content)
}

/// Parse SSH config content and extract hosts.
pub fn parse_ssh_config_content(content: &str) -> Result<Vec<DiscoveredHost>> {
    let mut hosts = Vec::new();
    let mut current_host: Option<SshConfigHost> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse the line into key-value
        let (key, value) = match parse_ssh_config_line(line) {
            Some(kv) => kv,
            None => continue,
        };

        match key.to_lowercase().as_str() {
            "host" => {
                // Save previous host if valid
                if let Some(host) = current_host.take() {
                    if let Some(discovered) = host.into_discovered() {
                        hosts.push(discovered);
                    }
                }

                // Start new host block
                // Handle multiple aliases on one line: "Host foo bar baz"
                let aliases: Vec<&str> = value.split_whitespace().collect();
                if let Some(first_alias) = aliases.first() {
                    // Skip wildcards and special patterns
                    if !first_alias.contains('*') && !first_alias.contains('?') {
                        current_host = Some(SshConfigHost::new(first_alias.to_string()));
                    }
                }
            }
            "hostname" => {
                if let Some(ref mut host) = current_host {
                    host.hostname = Some(value.to_string());
                }
            }
            "user" => {
                if let Some(ref mut host) = current_host {
                    host.user = Some(value.to_string());
                }
            }
            "identityfile" => {
                if let Some(ref mut host) = current_host {
                    host.identity_file = Some(expand_tilde(value));
                }
            }
            "port" => {
                if let Some(ref mut host) = current_host {
                    host.port = value.parse().ok();
                }
            }
            _ => {
                // Ignore other SSH config options
            }
        }
    }

    // Don't forget the last host
    if let Some(host) = current_host {
        if let Some(discovered) = host.into_discovered() {
            hosts.push(discovered);
        }
    }

    // Filter out hosts that are clearly not workers
    let hosts = hosts
        .into_iter()
        .filter(|h| is_potential_worker(&h.alias, &h.hostname))
        .collect();

    Ok(hosts)
}

/// Internal struct for parsing SSH config blocks.
struct SshConfigHost {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    identity_file: Option<String>,
    port: Option<u16>,
}

impl SshConfigHost {
    fn new(alias: String) -> Self {
        Self {
            alias,
            hostname: None,
            user: None,
            identity_file: None,
            port: None,
        }
    }

    fn into_discovered(self) -> Option<DiscoveredHost> {
        // Must have at least a hostname to be useful
        // If no hostname, use alias as hostname (common for simple configs)
        let hostname = self.hostname.unwrap_or_else(|| self.alias.clone());

        // Get current username as default
        let default_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "ubuntu".to_string());

        Some(DiscoveredHost {
            alias: self.alias,
            hostname,
            user: self.user.unwrap_or(default_user),
            identity_file: self.identity_file,
            port: self.port.unwrap_or(22),
            source: DiscoverySource::SshConfig,
        })
    }
}

/// Parse a single SSH config line into key-value pair.
fn parse_ssh_config_line(line: &str) -> Option<(&str, &str)> {
    // SSH config uses whitespace or = as separator
    // Examples:
    //   Host foo
    //   HostName=192.168.1.1
    //   User ubuntu

    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Try = separator first
    if let Some((key, value)) = line.split_once('=') {
        return Some((key.trim(), value.trim()));
    }

    // Try whitespace separator
    if let Some((key, value)) = line.split_once(char::is_whitespace) {
        return Some((key.trim(), value.trim()));
    }

    None
}

/// Expand ~ to home directory in paths.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).display().to_string();
        }
    }
    path.to_string()
}

/// Parse shell RC files for SSH aliases.
///
/// Looks for patterns like:
/// - `alias css='ssh -i ~/.ssh/key.pem ubuntu@192.168.1.100'`
/// - `alias csd="ssh user@host"`
/// - `alias foo='ssh host'`
pub fn parse_shell_aliases() -> Result<Vec<DiscoveredHost>> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let mut all_hosts = Vec::new();

    // List of shell RC files to check
    let rc_files = [
        (home.join(".bashrc"), DiscoverySource::Bashrc),
        (home.join(".zshrc"), DiscoverySource::Zshrc),
        (home.join(".bash_aliases"), DiscoverySource::BashAliases),
        (home.join(".zsh_aliases"), DiscoverySource::ZshAliases),
    ];

    for (path, source) in &rc_files {
        if path.exists() {
            match parse_shell_aliases_file(path, source.clone()) {
                Ok(hosts) => all_hosts.extend(hosts),
                Err(_) => continue, // Ignore parse errors in individual files
            }
        }
    }

    Ok(all_hosts)
}

/// Parse a shell RC file for SSH aliases.
pub fn parse_shell_aliases_file(path: &PathBuf, source: DiscoverySource) -> Result<Vec<DiscoveredHost>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read shell RC file: {}", path.display()))?;
    parse_shell_aliases_content(&content, source)
}

/// Parse shell alias content for SSH commands.
pub fn parse_shell_aliases_content(content: &str, source: DiscoverySource) -> Result<Vec<DiscoveredHost>> {
    use regex::Regex;

    let mut hosts = Vec::new();

    // Match alias definitions with ssh commands
    // Handles: alias NAME='ssh ...' or alias NAME="ssh ..."
    let alias_re = Regex::new(
        r#"(?m)^\s*alias\s+(\w+)\s*=\s*['"]ssh\s+(.*)['"]"#
    ).context("Failed to compile alias regex")?;

    // Extract -i identity file
    let identity_re = Regex::new(r"-i\s+(\S+)").context("Failed to compile identity regex")?;

    // Extract -p port
    let port_re = Regex::new(r"-p\s+(\d+)").context("Failed to compile port regex")?;

    for caps in alias_re.captures_iter(content) {
        let alias_name = match caps.get(1) {
            Some(m) => m.as_str().to_string(),
            None => continue,
        };
        let ssh_args = match caps.get(2) {
            Some(m) => m.as_str(),
            None => continue,
        };

        // Extract identity file if present
        let identity_file = identity_re
            .captures(ssh_args)
            .and_then(|c| c.get(1))
            .map(|m| expand_tilde(m.as_str()));

        // Extract port if present
        let port = port_re
            .captures(ssh_args)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u16>().ok())
            .unwrap_or(22);

        // Extract user@host from the end of the command
        // Strip all options first (anything starting with -)
        let args_without_options: Vec<&str> = ssh_args
            .split_whitespace()
            .filter(|s| !s.starts_with('-'))
            .filter(|s| {
                // Also filter out values that follow -i or -p
                if let Some(prev_idx) = ssh_args.find(s) {
                    if prev_idx > 0 {
                        let before = &ssh_args[..prev_idx].trim_end();
                        if before.ends_with("-i") || before.ends_with("-p") {
                            return false;
                        }
                    }
                }
                true
            })
            .collect();

        // The host specification is typically the last non-option argument
        let host_spec = match args_without_options.last() {
            Some(s) => *s,
            None => continue,
        };

        // Parse user@host or just host
        let (user, hostname) = if let Some((u, h)) = host_spec.split_once('@') {
            (u.to_string(), h.to_string())
        } else {
            // No user specified, use current user
            let default_user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "ubuntu".to_string());
            (default_user, host_spec.to_string())
        };

        // Skip if we couldn't extract a valid host
        if hostname.is_empty() {
            continue;
        }

        // Filter out non-workers
        if !is_potential_worker(&alias_name, &hostname) {
            continue;
        }

        hosts.push(DiscoveredHost {
            alias: alias_name,
            hostname,
            user,
            identity_file,
            port,
            source: source.clone(),
        });
    }

    Ok(hosts)
}

/// Discover all potential workers from all sources.
pub fn discover_all() -> Result<Vec<DiscoveredHost>> {
    let mut all_hosts = Vec::new();

    // Parse SSH config
    match parse_ssh_config() {
        Ok(hosts) => all_hosts.extend(hosts),
        Err(_) => {} // Ignore errors, continue with other sources
    }

    // Parse shell aliases
    match parse_shell_aliases() {
        Ok(hosts) => all_hosts.extend(hosts),
        Err(_) => {} // Ignore errors
    }

    // Deduplicate by hostname (keep first occurrence, which is typically SSH config)
    let mut seen_hostnames = std::collections::HashSet::new();
    all_hosts.retain(|h| seen_hostnames.insert(h.hostname.clone()));

    Ok(all_hosts)
}

/// Check if a host is potentially a worker (not a common non-worker host).
fn is_potential_worker(alias: &str, hostname: &str) -> bool {
    let skip_patterns = [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "localhost",
        "127.0.0.1",
        "::1",
    ];

    let skip_aliases = ["github", "gitlab", "bitbucket", "local"];

    // Check hostname
    for pattern in skip_patterns {
        if hostname.contains(pattern) {
            return false;
        }
    }

    // Check alias
    let alias_lower = alias.to_lowercase();
    for skip in skip_aliases {
        if alias_lower == skip {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_ssh_config() {
        let content = r#"
Host fmd
    HostName 51.222.245.56
    User ubuntu
    IdentityFile ~/.ssh/my_key.pem

Host yto
    HostName 37.187.75.150
    User root
    IdentityFile ~/.ssh/other_key.pem
    Port 2222
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 2);

        let fmd = &hosts[0];
        assert_eq!(fmd.alias, "fmd");
        assert_eq!(fmd.hostname, "51.222.245.56");
        assert_eq!(fmd.user, "ubuntu");
        assert!(fmd.identity_file.as_ref().unwrap().contains("my_key.pem"));
        assert_eq!(fmd.port, 22);
        assert_eq!(fmd.source, DiscoverySource::SshConfig);

        let yto = &hosts[1];
        assert_eq!(yto.alias, "yto");
        assert_eq!(yto.hostname, "37.187.75.150");
        assert_eq!(yto.user, "root");
        assert_eq!(yto.port, 2222);
    }

    #[test]
    fn test_skip_wildcard_hosts() {
        let content = r#"
Host *
    ServerAliveInterval 60

Host worker1
    HostName 192.168.1.10
    User ubuntu
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "worker1");
    }

    #[test]
    fn test_skip_github() {
        let content = r#"
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_key

Host worker1
    HostName 192.168.1.10
    User ubuntu
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "worker1");
    }

    #[test]
    fn test_handle_multiple_aliases() {
        let content = r#"
Host foo bar baz
    HostName 192.168.1.10
    User ubuntu
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        // Should use first alias
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "foo");
    }

    #[test]
    fn test_handle_equals_separator() {
        let content = r#"
Host worker
    HostName=192.168.1.10
    User=ubuntu
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "192.168.1.10");
        assert_eq!(hosts[0].user, "ubuntu");
    }

    #[test]
    fn test_handle_comments() {
        let content = r#"
# This is a comment
Host worker1
    # Another comment
    HostName 192.168.1.10
    User ubuntu
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "worker1");
    }

    #[test]
    fn test_empty_config() {
        let content = "";
        let hosts = parse_ssh_config_content(content).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_host_without_hostname_uses_alias() {
        let content = r#"
Host myserver
    User ubuntu
    IdentityFile ~/.ssh/key.pem
"#;

        let hosts = parse_ssh_config_content(content).unwrap();
        assert_eq!(hosts.len(), 1);
        // When no HostName, alias is used as hostname
        assert_eq!(hosts[0].hostname, "myserver");
    }

    #[test]
    fn test_expand_tilde() {
        let path = "~/.ssh/key.pem";
        let expanded = expand_tilde(path);
        assert!(!expanded.starts_with("~"));
        assert!(expanded.contains(".ssh/key.pem"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let path = "/absolute/path/key.pem";
        assert_eq!(expand_tilde(path), path);
    }

    #[test]
    fn test_is_potential_worker() {
        assert!(is_potential_worker("worker1", "192.168.1.10"));
        assert!(is_potential_worker("css", "209.145.54.164"));
        assert!(!is_potential_worker("github", "github.com"));
        assert!(!is_potential_worker("local", "localhost"));
        assert!(!is_potential_worker("home", "127.0.0.1"));
    }

    // Shell alias parsing tests

    #[test]
    fn test_parse_shell_aliases_basic() {
        let content = r#"
# Some other config
export PATH="/usr/local/bin:$PATH"

alias ll='ls -la'
alias css='ssh -i ~/.ssh/key.pem ubuntu@192.168.1.100'
alias csd='ssh root@10.0.0.5'
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert_eq!(hosts.len(), 2);

        let css = hosts.iter().find(|h| h.alias == "css").unwrap();
        assert_eq!(css.hostname, "192.168.1.100");
        assert_eq!(css.user, "ubuntu");
        assert!(css.identity_file.is_some());
        assert_eq!(css.source, DiscoverySource::Bashrc);

        let csd = hosts.iter().find(|h| h.alias == "csd").unwrap();
        assert_eq!(csd.hostname, "10.0.0.5");
        assert_eq!(csd.user, "root");
    }

    #[test]
    fn test_parse_shell_aliases_double_quotes() {
        let content = r#"
alias server="ssh -i ~/.ssh/id_rsa admin@example.com"
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Zshrc).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "server");
        assert_eq!(hosts[0].hostname, "example.com");
        assert_eq!(hosts[0].user, "admin");
    }

    #[test]
    fn test_parse_shell_aliases_with_port() {
        let content = r#"
alias custom='ssh -p 2222 user@192.168.1.50'
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].port, 2222);
    }

    #[test]
    fn test_parse_shell_aliases_simple_host() {
        let content = r#"
alias myserver='ssh myserver.example.com'
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "myserver.example.com");
        // User should default to current user or ubuntu
        assert!(!hosts[0].user.is_empty());
    }

    #[test]
    fn test_parse_shell_aliases_skips_localhost() {
        let content = r#"
alias local='ssh localhost'
alias loopback='ssh 127.0.0.1'
alias remote='ssh 192.168.1.1'
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "remote");
    }

    #[test]
    fn test_parse_shell_aliases_skips_non_ssh() {
        let content = r#"
alias ll='ls -la'
alias grep='grep --color=auto'
alias ssh_host='ssh worker@192.168.1.10'
"#;

        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "ssh_host");
    }

    #[test]
    fn test_parse_shell_aliases_empty() {
        let content = "";
        let hosts = parse_shell_aliases_content(content, DiscoverySource::Bashrc).unwrap();
        assert!(hosts.is_empty());
    }
}
