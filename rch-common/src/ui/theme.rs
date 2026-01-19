//! RCH brand colors and semantic styles.
//!
//! Provides a unified theme for consistent visual branding across all RCH commands.
//! All color constants are valid hex colors that work with `rich_rust`.

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::{Color, Style};

use crate::types::WorkerStatus;

/// RCH brand colors and semantic styles.
///
/// # Design Philosophy
///
/// - **Purple**: Compilation/build theme - sophisticated, technical
/// - **Cyan**: Data transfer theme - clean, digital
/// - **Amber**: Attention/highlights - warm, visible
///
/// # Example (with rich-ui feature)
///
/// ```ignore
/// use rch_common::ui::RchTheme;
///
/// let style = RchTheme::success();
/// // Use style with rich_rust Console
/// ```
pub struct RchTheme;

impl RchTheme {
    // ═══════════════════════════════════════════════════════════════════════
    // BRAND COLORS
    // ═══════════════════════════════════════════════════════════════════════

    /// Primary brand color - Purple (compilation/build theme).
    pub const PRIMARY: &'static str = "#7C3AED";

    /// Secondary brand color - Cyan (data/transfer theme).
    pub const SECONDARY: &'static str = "#06B6D4";

    /// Accent color - Amber (highlights, attention).
    pub const ACCENT: &'static str = "#F59E0B";

    // ═══════════════════════════════════════════════════════════════════════
    // SEMANTIC COLORS
    // ═══════════════════════════════════════════════════════════════════════

    /// Success state - Green.
    pub const SUCCESS: &'static str = "#10B981";

    /// Warning state - Amber.
    pub const WARNING: &'static str = "#F59E0B";

    /// Error state - Red.
    pub const ERROR: &'static str = "#EF4444";

    /// Informational - Blue.
    pub const INFO: &'static str = "#3B82F6";

    // ═══════════════════════════════════════════════════════════════════════
    // WORKER STATUS COLORS
    // These match the WorkerStatus enum from rch-common/types
    // ═══════════════════════════════════════════════════════════════════════

    /// Worker is healthy and accepting work - Green.
    pub const STATUS_HEALTHY: &'static str = "#10B981";

    /// Worker is degraded (slow, high error rate) - Amber.
    pub const STATUS_DEGRADED: &'static str = "#F59E0B";

    /// Worker is unreachable (connection failed) - Red.
    pub const STATUS_UNREACHABLE: &'static str = "#EF4444";

    /// Worker is draining (no new work) - Purple.
    pub const STATUS_DRAINING: &'static str = "#8B5CF6";

    /// Worker is disabled (admin disabled) - Gray.
    pub const STATUS_DISABLED: &'static str = "#6B7280";

    // ═══════════════════════════════════════════════════════════════════════
    // TEXT COLORS
    // ═══════════════════════════════════════════════════════════════════════

    /// Muted text (secondary information) - Gray-400.
    pub const MUTED: &'static str = "#9CA3AF";

    /// Dim text (tertiary information) - Gray-500.
    pub const DIM: &'static str = "#6B7280";

    /// Bright text (emphasis) - Gray-50.
    pub const BRIGHT: &'static str = "#F9FAFB";

    // ═══════════════════════════════════════════════════════════════════════
    // STYLE GENERATORS (require rich-ui feature)
    // ═══════════════════════════════════════════════════════════════════════

    /// Create style for success messages.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn success() -> Style {
        Style::new().color(Color::parse(Self::SUCCESS).unwrap_or_default())
    }

    /// Create style for error messages (bold for emphasis).
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn error() -> Style {
        Style::new()
            .bold()
            .color(Color::parse(Self::ERROR).unwrap_or_default())
    }

    /// Create style for warning messages.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn warning() -> Style {
        Style::new().color(Color::parse(Self::WARNING).unwrap_or_default())
    }

    /// Create style for informational messages.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn info() -> Style {
        Style::new().color(Color::parse(Self::INFO).unwrap_or_default())
    }

    /// Create style for muted/secondary text.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn muted() -> Style {
        Style::new().color(Color::parse(Self::MUTED).unwrap_or_default())
    }

    /// Create style for dim/tertiary text.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn dim() -> Style {
        Style::new()
            .dim()
            .color(Color::parse(Self::DIM).unwrap_or_default())
    }

    /// Create style for primary brand elements.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn primary() -> Style {
        Style::new().color(Color::parse(Self::PRIMARY).unwrap_or_default())
    }

    /// Create style for secondary brand elements.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn secondary() -> Style {
        Style::new().color(Color::parse(Self::SECONDARY).unwrap_or_default())
    }

    /// Create style for accent/highlight elements.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn accent() -> Style {
        Style::new().color(Color::parse(Self::ACCENT).unwrap_or_default())
    }

    /// Create style for worker status based on string.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn worker_status_str(status: &str) -> Style {
        let color = match status.to_lowercase().as_str() {
            "healthy" => Self::STATUS_HEALTHY,
            "degraded" => Self::STATUS_DEGRADED,
            "unreachable" => Self::STATUS_UNREACHABLE,
            "draining" => Self::STATUS_DRAINING,
            "disabled" => Self::STATUS_DISABLED,
            _ => Self::MUTED,
        };
        Style::new().color(Color::parse(color).unwrap_or_default())
    }

    /// Create style for worker status enum.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn for_worker_status(status: WorkerStatus) -> Style {
        let color = match status {
            WorkerStatus::Healthy => Self::STATUS_HEALTHY,
            WorkerStatus::Degraded => Self::STATUS_DEGRADED,
            WorkerStatus::Unreachable => Self::STATUS_UNREACHABLE,
            WorkerStatus::Draining => Self::STATUS_DRAINING,
            WorkerStatus::Disabled => Self::STATUS_DISABLED,
        };
        Style::new().color(Color::parse(color).unwrap_or_default())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // COMPOSITE STYLES (require rich-ui feature)
    // ═══════════════════════════════════════════════════════════════════════

    /// Style for table headers.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn table_header() -> Style {
        Style::new()
            .bold()
            .color(Color::parse(Self::BRIGHT).unwrap_or_default())
    }

    /// Style for table borders.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn table_border() -> Style {
        Style::new().color(Color::parse(Self::PRIMARY).unwrap_or_default())
    }

    /// Style for panel titles.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn panel_title() -> Style {
        Style::new()
            .bold()
            .color(Color::parse(Self::SECONDARY).unwrap_or_default())
    }

    /// Style for command/code text.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn code() -> Style {
        Style::new().color(Color::parse(Self::SECONDARY).unwrap_or_default())
    }

    /// Style for paths/filenames.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn path() -> Style {
        Style::new()
            .italic()
            .color(Color::parse(Self::INFO).unwrap_or_default())
    }

    /// Style for numbers/metrics.
    #[cfg(feature = "rich-ui")]
    #[must_use]
    pub fn number() -> Style {
        Style::new().color(Color::parse(Self::ACCENT).unwrap_or_default())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // COLOR LOOKUP (always available)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get color hex code for a worker status.
    #[must_use]
    pub const fn color_for_worker_status(status: WorkerStatus) -> &'static str {
        match status {
            WorkerStatus::Healthy => Self::STATUS_HEALTHY,
            WorkerStatus::Degraded => Self::STATUS_DEGRADED,
            WorkerStatus::Unreachable => Self::STATUS_UNREACHABLE,
            WorkerStatus::Draining => Self::STATUS_DRAINING,
            WorkerStatus::Disabled => Self::STATUS_DISABLED,
        }
    }

    /// Get color hex code for a status string (case-insensitive).
    #[must_use]
    pub fn color_for_status_str(status: &str) -> &'static str {
        match status.to_lowercase().as_str() {
            "healthy" => Self::STATUS_HEALTHY,
            "degraded" => Self::STATUS_DEGRADED,
            "unreachable" => Self::STATUS_UNREACHABLE,
            "draining" => Self::STATUS_DRAINING,
            "disabled" => Self::STATUS_DISABLED,
            "success" | "ok" => Self::SUCCESS,
            "warning" | "warn" => Self::WARNING,
            "error" | "fail" | "failed" => Self::ERROR,
            "info" => Self::INFO,
            _ => Self::MUTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_color_constants_are_valid_hex() {
        // All color constants should be 7-character hex strings (#RRGGBB)
        let colors = [
            RchTheme::PRIMARY,
            RchTheme::SECONDARY,
            RchTheme::ACCENT,
            RchTheme::SUCCESS,
            RchTheme::WARNING,
            RchTheme::ERROR,
            RchTheme::INFO,
            RchTheme::STATUS_HEALTHY,
            RchTheme::STATUS_DEGRADED,
            RchTheme::STATUS_UNREACHABLE,
            RchTheme::STATUS_DRAINING,
            RchTheme::STATUS_DISABLED,
            RchTheme::MUTED,
            RchTheme::DIM,
            RchTheme::BRIGHT,
        ];

        for color in colors {
            assert!(color.starts_with('#'), "Color should start with #: {color}");
            assert_eq!(color.len(), 7, "Color should be 7 chars: {color}");
            assert!(
                color[1..].chars().all(|c| c.is_ascii_hexdigit()),
                "Color should be valid hex: {color}"
            );
        }
    }

    #[test]
    fn test_color_for_worker_status() {
        assert_eq!(
            RchTheme::color_for_worker_status(WorkerStatus::Healthy),
            RchTheme::STATUS_HEALTHY
        );
        assert_eq!(
            RchTheme::color_for_worker_status(WorkerStatus::Degraded),
            RchTheme::STATUS_DEGRADED
        );
        assert_eq!(
            RchTheme::color_for_worker_status(WorkerStatus::Unreachable),
            RchTheme::STATUS_UNREACHABLE
        );
        assert_eq!(
            RchTheme::color_for_worker_status(WorkerStatus::Draining),
            RchTheme::STATUS_DRAINING
        );
        assert_eq!(
            RchTheme::color_for_worker_status(WorkerStatus::Disabled),
            RchTheme::STATUS_DISABLED
        );
    }

    #[test]
    fn test_color_for_status_str() {
        // Case insensitive
        assert_eq!(
            RchTheme::color_for_status_str("HEALTHY"),
            RchTheme::STATUS_HEALTHY
        );
        assert_eq!(
            RchTheme::color_for_status_str("healthy"),
            RchTheme::STATUS_HEALTHY
        );
        assert_eq!(
            RchTheme::color_for_status_str("Healthy"),
            RchTheme::STATUS_HEALTHY
        );

        // Aliases
        assert_eq!(RchTheme::color_for_status_str("success"), RchTheme::SUCCESS);
        assert_eq!(RchTheme::color_for_status_str("ok"), RchTheme::SUCCESS);
        assert_eq!(RchTheme::color_for_status_str("error"), RchTheme::ERROR);
        assert_eq!(RchTheme::color_for_status_str("fail"), RchTheme::ERROR);
        assert_eq!(RchTheme::color_for_status_str("failed"), RchTheme::ERROR);

        // Unknown -> muted
        assert_eq!(RchTheme::color_for_status_str("unknown"), RchTheme::MUTED);
        assert_eq!(RchTheme::color_for_status_str(""), RchTheme::MUTED);
    }

    #[test]
    fn test_all_status_colors_are_distinct() {
        let colors = [
            RchTheme::STATUS_HEALTHY,
            RchTheme::STATUS_DEGRADED,
            RchTheme::STATUS_UNREACHABLE,
            RchTheme::STATUS_DRAINING,
            RchTheme::STATUS_DISABLED,
        ];

        // Check all pairs are distinct
        for (i, &c1) in colors.iter().enumerate() {
            for &c2 in &colors[i + 1..] {
                assert_ne!(c1, c2, "Status colors should be distinct");
            }
        }
    }

    #[cfg(feature = "rich-ui")]
    mod rich_ui_tests {
        use super::*;
        use rich_rust::prelude::Color;

        #[test]
        fn test_all_colors_parse_with_rich_rust() {
            // Ensure no color constant is malformed
            assert!(Color::parse(RchTheme::PRIMARY).is_ok());
            assert!(Color::parse(RchTheme::SECONDARY).is_ok());
            assert!(Color::parse(RchTheme::ACCENT).is_ok());
            assert!(Color::parse(RchTheme::SUCCESS).is_ok());
            assert!(Color::parse(RchTheme::WARNING).is_ok());
            assert!(Color::parse(RchTheme::ERROR).is_ok());
            assert!(Color::parse(RchTheme::INFO).is_ok());
            assert!(Color::parse(RchTheme::STATUS_HEALTHY).is_ok());
            assert!(Color::parse(RchTheme::STATUS_DEGRADED).is_ok());
            assert!(Color::parse(RchTheme::STATUS_UNREACHABLE).is_ok());
            assert!(Color::parse(RchTheme::STATUS_DRAINING).is_ok());
            assert!(Color::parse(RchTheme::STATUS_DISABLED).is_ok());
            assert!(Color::parse(RchTheme::MUTED).is_ok());
            assert!(Color::parse(RchTheme::DIM).is_ok());
            assert!(Color::parse(RchTheme::BRIGHT).is_ok());
        }

        #[test]
        fn test_styles_dont_panic() {
            // Ensure style generators don't panic
            let _ = RchTheme::success();
            let _ = RchTheme::error();
            let _ = RchTheme::warning();
            let _ = RchTheme::info();
            let _ = RchTheme::muted();
            let _ = RchTheme::dim();
            let _ = RchTheme::primary();
            let _ = RchTheme::secondary();
            let _ = RchTheme::accent();
            let _ = RchTheme::table_header();
            let _ = RchTheme::table_border();
            let _ = RchTheme::panel_title();
            let _ = RchTheme::code();
            let _ = RchTheme::path();
            let _ = RchTheme::number();
        }

        #[test]
        fn test_worker_status_styles() {
            // String-based
            let _ = RchTheme::worker_status_str("healthy");
            let _ = RchTheme::worker_status_str("unknown"); // Should not panic

            // Enum-based
            let _ = RchTheme::for_worker_status(WorkerStatus::Healthy);
            let _ = RchTheme::for_worker_status(WorkerStatus::Degraded);
            let _ = RchTheme::for_worker_status(WorkerStatus::Unreachable);
            let _ = RchTheme::for_worker_status(WorkerStatus::Draining);
            let _ = RchTheme::for_worker_status(WorkerStatus::Disabled);
        }
    }
}
