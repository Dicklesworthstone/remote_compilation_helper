//! ConfigDisplay - Rich terminal display for `rch config show` command.
//!
//! This module provides context-aware configuration display using rich_rust.
//! Falls back to plain text when rich output is not available.

use crate::commands::ConfigShowResponse;
use crate::ui::console::RchConsole;

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

use rch_common::ui::{Icons, OutputContext, RchTheme};

/// ConfigDisplay renders configuration with rich formatting.
///
/// Displays:
/// - Hierarchical tree view of configuration sections
/// - Source indicators for each value
/// - Syntax highlighting for value types
pub struct ConfigDisplay<'a> {
    config: &'a ConfigShowResponse,
    context: OutputContext,
    show_sources: bool,
}

impl<'a> ConfigDisplay<'a> {
    /// Create a new ConfigDisplay from config response.
    #[must_use]
    pub fn new(config: &'a ConfigShowResponse, context: OutputContext, show_sources: bool) -> Self {
        Self {
            config,
            context,
            show_sources,
        }
    }

    /// Create from config with auto-detected context.
    #[must_use]
    pub fn from_config(config: &'a ConfigShowResponse, show_sources: bool) -> Self {
        Self::new(config, OutputContext::detect(), show_sources)
    }

    /// Render the configuration display using RchConsole.
    pub fn render(&self, console: &RchConsole) {
        if console.is_machine() {
            // JSON mode - don't render, caller should use print_json
            return;
        }

        #[cfg(feature = "rich-ui")]
        if console.is_rich() {
            self.render_rich(console);
            return;
        }

        self.render_plain(console);
    }

    /// Render rich output using rich_rust.
    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, console: &RchConsole) {
        // Build the configuration tree as a string
        let mut lines = Vec::new();

        // General section
        lines.push(format!("{} [general]", Icons::tree_branch(self.context)));
        self.push_config_line(
            &mut lines,
            "  ",
            "enabled",
            &self.config.general.enabled.to_string(),
            "general.enabled",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "log_level",
            &format!("\"{}\"", self.config.general.log_level),
            "general.log_level",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "socket_path",
            &format!("\"{}\"", self.config.general.socket_path),
            "general.socket_path",
        );

        // Compilation section
        lines.push(format!(
            "{} [compilation]",
            Icons::tree_branch(self.context)
        ));
        self.push_config_line(
            &mut lines,
            "  ",
            "confidence_threshold",
            &self.config.compilation.confidence_threshold.to_string(),
            "compilation.confidence_threshold",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "min_local_time_ms",
            &self.config.compilation.min_local_time_ms.to_string(),
            "compilation.min_local_time_ms",
        );

        // Transfer section
        lines.push(format!("{} [transfer]", Icons::tree_branch(self.context)));
        self.push_config_line(
            &mut lines,
            "  ",
            "compression_level",
            &self.config.transfer.compression_level.to_string(),
            "transfer.compression_level",
        );
        let patterns = format!("{:?}", self.config.transfer.exclude_patterns);
        self.push_config_line(
            &mut lines,
            "  ",
            "exclude_patterns",
            &patterns,
            "transfer.exclude_patterns",
        );

        // Environment section
        lines.push(format!(
            "{} [environment]",
            Icons::tree_branch(self.context)
        ));
        let allowlist = format!("{:?}", self.config.environment.allowlist);
        self.push_config_line(
            &mut lines,
            "  ",
            "allowlist",
            &allowlist,
            "environment.allowlist",
        );

        // Circuit section
        lines.push(format!("{} [circuit]", Icons::tree_branch(self.context)));
        self.push_config_line(
            &mut lines,
            "  ",
            "failure_threshold",
            &self.config.circuit.failure_threshold.to_string(),
            "circuit.failure_threshold",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "success_threshold",
            &self.config.circuit.success_threshold.to_string(),
            "circuit.success_threshold",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "error_rate_threshold",
            &self.config.circuit.error_rate_threshold.to_string(),
            "circuit.error_rate_threshold",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "window_secs",
            &self.config.circuit.window_secs.to_string(),
            "circuit.window_secs",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "open_cooldown_secs",
            &self.config.circuit.open_cooldown_secs.to_string(),
            "circuit.open_cooldown_secs",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "half_open_max_probes",
            &self.config.circuit.half_open_max_probes.to_string(),
            "circuit.half_open_max_probes",
        );

        // Output section
        lines.push(format!("{} [output]", Icons::tree_end(self.context)));
        self.push_config_line(
            &mut lines,
            "  ",
            "visibility",
            &format!("{:?}", self.config.output.visibility),
            "output.visibility",
        );
        self.push_config_line(
            &mut lines,
            "  ",
            "first_run_complete",
            &self.config.output.first_run_complete.to_string(),
            "output.first_run_complete",
        );

        let content = lines.join("\n");
        let panel = Panel::from_text(&content)
            .title("RCH Configuration")
            .border_style(RchTheme::secondary())
            .rounded();

        console.print_renderable(&panel);

        // Sources summary
        if self.show_sources && !self.config.sources.is_empty() {
            console.line();
            self.render_sources_rich(console);
        }
    }

    /// Push a config line with optional source annotation.
    fn push_config_line(
        &self,
        lines: &mut Vec<String>,
        indent: &str,
        key: &str,
        value: &str,
        full_key: &str,
    ) {
        let source_suffix = if self.show_sources {
            self.get_source_label(full_key)
                .map(|s| format!("  [{}]", s))
                .unwrap_or_default()
        } else {
            String::new()
        };

        lines.push(format!(
            "{}{}{} {} = {}{}",
            indent,
            Icons::tree_branch(self.context),
            Icons::tree_horizontal(self.context),
            key,
            value,
            source_suffix
        ));
    }

    /// Get source label for a config key.
    fn get_source_label(&self, key: &str) -> Option<String> {
        self.config.value_sources.as_ref().and_then(|sources| {
            sources
                .iter()
                .find(|s| s.key == key)
                .map(|s| s.source.clone())
        })
    }

    /// Render sources summary panel.
    #[cfg(feature = "rich-ui")]
    fn render_sources_rich(&self, console: &RchConsole) {
        let info = Icons::info(self.context);
        let mut lines = vec![format!("{info} Configuration sources (priority order):")];
        for (i, source) in self.config.sources.iter().enumerate() {
            let num = i + 1;
            lines.push(format!("  {num}. {source}"));
        }
        let content = lines.join("\n");
        console.print_plain(&content);
    }

    /// Render plain text output (no rich formatting).
    fn render_plain(&self, console: &RchConsole) {
        console.print_plain("=== RCH Configuration ===");
        console.print_plain("");

        // General section
        console.print_plain("[general]");
        self.print_plain_value(
            console,
            "enabled",
            &self.config.general.enabled.to_string(),
            "general.enabled",
        );
        self.print_plain_value(
            console,
            "log_level",
            &format!("\"{}\"", self.config.general.log_level),
            "general.log_level",
        );
        self.print_plain_value(
            console,
            "socket_path",
            &format!("\"{}\"", self.config.general.socket_path),
            "general.socket_path",
        );

        // Compilation section
        console.print_plain("");
        console.print_plain("[compilation]");
        self.print_plain_value(
            console,
            "confidence_threshold",
            &self.config.compilation.confidence_threshold.to_string(),
            "compilation.confidence_threshold",
        );
        self.print_plain_value(
            console,
            "min_local_time_ms",
            &self.config.compilation.min_local_time_ms.to_string(),
            "compilation.min_local_time_ms",
        );

        // Transfer section
        console.print_plain("");
        console.print_plain("[transfer]");
        self.print_plain_value(
            console,
            "compression_level",
            &self.config.transfer.compression_level.to_string(),
            "transfer.compression_level",
        );
        let patterns = format!("{:?}", self.config.transfer.exclude_patterns);
        self.print_plain_value(
            console,
            "exclude_patterns",
            &patterns,
            "transfer.exclude_patterns",
        );

        // Environment section
        console.print_plain("");
        console.print_plain("[environment]");
        let allowlist = format!("{:?}", self.config.environment.allowlist);
        self.print_plain_value(console, "allowlist", &allowlist, "environment.allowlist");

        // Circuit section
        console.print_plain("");
        console.print_plain("[circuit]");
        self.print_plain_value(
            console,
            "failure_threshold",
            &self.config.circuit.failure_threshold.to_string(),
            "circuit.failure_threshold",
        );
        self.print_plain_value(
            console,
            "success_threshold",
            &self.config.circuit.success_threshold.to_string(),
            "circuit.success_threshold",
        );
        self.print_plain_value(
            console,
            "error_rate_threshold",
            &self.config.circuit.error_rate_threshold.to_string(),
            "circuit.error_rate_threshold",
        );
        self.print_plain_value(
            console,
            "window_secs",
            &self.config.circuit.window_secs.to_string(),
            "circuit.window_secs",
        );
        self.print_plain_value(
            console,
            "open_cooldown_secs",
            &self.config.circuit.open_cooldown_secs.to_string(),
            "circuit.open_cooldown_secs",
        );
        self.print_plain_value(
            console,
            "half_open_max_probes",
            &self.config.circuit.half_open_max_probes.to_string(),
            "circuit.half_open_max_probes",
        );

        // Output section
        console.print_plain("");
        console.print_plain("[output]");
        self.print_plain_value(
            console,
            "visibility",
            &format!("{:?}", self.config.output.visibility),
            "output.visibility",
        );
        self.print_plain_value(
            console,
            "first_run_complete",
            &self.config.output.first_run_complete.to_string(),
            "output.first_run_complete",
        );

        // Sources
        if self.show_sources && !self.config.sources.is_empty() {
            console.print_plain("");
            let info = Icons::info(self.context);
            console.print_plain(&format!("{info} Configuration sources (priority order):"));
            for (i, source) in self.config.sources.iter().enumerate() {
                let num = i + 1;
                console.print_plain(&format!("  {num}. {source}"));
            }
        }
    }

    /// Print a plain text config value with optional source.
    fn print_plain_value(&self, console: &RchConsole, key: &str, value: &str, full_key: &str) {
        let source_suffix = if self.show_sources {
            self.get_source_label(full_key)
                .map(|s| format!("  # from {}", s))
                .unwrap_or_default()
        } else {
            String::new()
        };

        console.print_plain(&format!("  {} = {}{}", key, value, source_suffix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{
        ConfigCircuitSection, ConfigCompilationSection, ConfigEnvironmentSection,
        ConfigGeneralSection, ConfigOutputSection, ConfigSelfHealingSection, ConfigTransferSection,
        ConfigValueSourceInfo,
    };
    use rch_common::OutputVisibility;

    fn sample_config() -> ConfigShowResponse {
        ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: true,
                log_level: "info".to_string(),
                socket_path: "/tmp/rch.sock".to_string(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: 0.8,
                min_local_time_ms: 1000,
            },
            transfer: ConfigTransferSection {
                compression_level: 6,
                exclude_patterns: vec!["target".to_string(), "node_modules".to_string()],
            },
            environment: ConfigEnvironmentSection {
                allowlist: vec!["RUSTFLAGS".to_string()],
            },
            circuit: ConfigCircuitSection {
                failure_threshold: 3,
                success_threshold: 2,
                error_rate_threshold: 0.5,
                window_secs: 60,
                open_cooldown_secs: 30,
                half_open_max_probes: 3,
            },
            output: ConfigOutputSection {
                visibility: OutputVisibility::Verbose,
                first_run_complete: true,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: true,
                auto_start_cooldown_secs: 60,
                auto_start_timeout_secs: 10,
            },
            sources: vec![
                "Environment variables (RCH_*)".to_string(),
                "Project config: .rch/config.toml".to_string(),
            ],
            value_sources: Some(vec![
                ConfigValueSourceInfo {
                    key: "general.enabled".to_string(),
                    value: "true".to_string(),
                    source: "default".to_string(),
                },
                ConfigValueSourceInfo {
                    key: "general.log_level".to_string(),
                    value: "info".to_string(),
                    source: "config file".to_string(),
                },
            ]),
        }
    }

    #[test]
    fn test_config_display_creation() {
        let config = sample_config();
        let ctx = OutputContext::Plain;
        let display = ConfigDisplay::new(&config, ctx, true);
        assert_eq!(display.context, OutputContext::Plain);
        assert!(display.show_sources);
    }

    #[test]
    fn test_config_display_from_config() {
        let config = sample_config();
        let display = ConfigDisplay::from_config(&config, false);
        let _ = display.context; // Should not panic
        assert!(!display.show_sources);
    }

    #[test]
    fn test_get_source_label_found() {
        let config = sample_config();
        let display = ConfigDisplay::new(&config, OutputContext::Plain, true);
        let source = display.get_source_label("general.enabled");
        assert_eq!(source, Some("default".to_string()));
    }

    #[test]
    fn test_get_source_label_not_found() {
        let config = sample_config();
        let display = ConfigDisplay::new(&config, OutputContext::Plain, true);
        let source = display.get_source_label("unknown.key");
        assert!(source.is_none());
    }

    #[test]
    fn test_get_source_label_no_sources() {
        let mut config = sample_config();
        config.value_sources = None;
        let display = ConfigDisplay::new(&config, OutputContext::Plain, true);
        let source = display.get_source_label("general.enabled");
        assert!(source.is_none());
    }

    #[test]
    fn test_render_plain_mode() {
        let config = sample_config();
        let console = RchConsole::with_context(OutputContext::Plain);
        let display = ConfigDisplay::new(&config, OutputContext::Plain, true);
        // Should not panic
        display.render(&console);
    }

    #[test]
    fn test_render_plain_mode_no_sources() {
        let config = sample_config();
        let console = RchConsole::with_context(OutputContext::Plain);
        let display = ConfigDisplay::new(&config, OutputContext::Plain, false);
        // Should not panic
        display.render(&console);
    }

    #[test]
    fn test_render_machine_mode_no_output() {
        let config = sample_config();
        let console = RchConsole::with_context(OutputContext::Machine);
        let display = ConfigDisplay::new(&config, OutputContext::Machine, true);
        // Should not panic, should do nothing
        display.render(&console);
    }
}
