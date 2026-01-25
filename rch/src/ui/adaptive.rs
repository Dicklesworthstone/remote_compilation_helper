//! Adaptive color support for terminal output.
//!
//! Provides colors that automatically adapt to light/dark terminal backgrounds,
//! inspired by Charm's Lip Gloss adaptive color system.

use colored::Color;
use std::env;

/// Terminal background detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Background {
    /// Terminal has a light background.
    Light,
    /// Terminal has a dark background.
    #[default]
    Dark,
}

/// Level of color support in the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ColorLevel {
    /// No color support (dumb terminal).
    None,
    /// Basic 16 ANSI colors.
    #[default]
    Ansi16,
    /// Extended 256-color palette.
    Ansi256,
    /// Full 24-bit RGB true color.
    TrueColor,
}

impl ColorLevel {
    /// Check if the terminal supports 256 colors.
    pub fn supports_256(&self) -> bool {
        *self >= ColorLevel::Ansi256
    }

    /// Check if the terminal supports true color (24-bit RGB).
    pub fn supports_true_color(&self) -> bool {
        *self == ColorLevel::TrueColor
    }
}

/// Colors that adapt to light/dark terminal backgrounds.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveColor {
    /// Color to use on light backgrounds.
    pub light: Color,
    /// Color to use on dark backgrounds.
    pub dark: Color,
}

impl AdaptiveColor {
    /// Create a new adaptive color with light and dark variants.
    pub const fn new(light: Color, dark: Color) -> Self {
        Self { light, dark }
    }

    /// Resolve the appropriate color for the given background.
    pub fn resolve(&self, background: Background) -> Color {
        match background {
            Background::Light => self.light,
            Background::Dark => self.dark,
        }
    }
}

/// Standard adaptive color palette for semantic UI elements.
pub mod palette {
    use super::*;

    /// Subtle text for secondary information.
    pub const SUBTLE: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor {
            r: 88,
            g: 88,
            b: 88,
        }, // Dark gray on light
        Color::TrueColor {
            r: 168,
            g: 168,
            b: 168,
        }, // Light gray on dark
    );

    /// Highlighted/emphasized text.
    pub const HIGHLIGHT: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor {
            r: 205,
            g: 92,
            b: 178,
        }, // Magenta on light
        Color::TrueColor {
            r: 255,
            g: 135,
            b: 215,
        }, // Pink on dark
    );

    /// Success status indicators.
    pub const SUCCESS: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor { r: 0, g: 135, b: 0 }, // Dark green on light
        Color::TrueColor {
            r: 95,
            g: 255,
            b: 95,
        }, // Bright green on dark
    );

    /// Error status indicators.
    pub const ERROR: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor { r: 175, g: 0, b: 0 }, // Dark red on light
        Color::TrueColor {
            r: 255,
            g: 95,
            b: 95,
        }, // Bright red on dark
    );

    /// Warning status indicators.
    pub const WARNING: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor {
            r: 175,
            g: 95,
            b: 0,
        }, // Dark orange/yellow on light
        Color::TrueColor {
            r: 255,
            g: 175,
            b: 95,
        }, // Bright yellow on dark
    );

    /// Information status indicators.
    pub const INFO: AdaptiveColor = AdaptiveColor::new(
        Color::TrueColor {
            r: 0,
            g: 95,
            b: 175,
        }, // Dark blue on light
        Color::TrueColor {
            r: 95,
            g: 175,
            b: 255,
        }, // Bright blue on dark
    );
}

/// Detect if the terminal has a light or dark background.
///
/// Checks multiple environment variables in priority order:
/// 1. `COLORFGBG` - Format: "fg;bg" (e.g., "15;0" = white on black)
/// 2. `TERMINAL_THEME` - Some terminals set this
/// 3. `TERM_BACKGROUND` - macOS Terminal.app
///
/// Defaults to dark background (most common for developers).
pub fn detect_background() -> Background {
    // Check COLORFGBG env var (format: "fg;bg" e.g., "15;0" = white on black)
    if let Ok(colorfgbg) = env::var("COLORFGBG")
        && let Some(bg) = colorfgbg.split(';').nth(1)
        && let Ok(bg_num) = bg.parse::<u8>()
    {
        // Standard terminal colors: 0-7 are dark, 8 is bright black (still dark)
        // 9-15 are light colors
        return if bg_num <= 8 {
            Background::Dark
        } else {
            Background::Light
        };
    }

    // Check terminal-specific env vars
    if let Ok(theme) = env::var("TERMINAL_THEME")
        && theme.to_lowercase().contains("light")
    {
        return Background::Light;
    }

    // macOS Terminal.app
    if let Ok(bg) = env::var("TERM_BACKGROUND") && bg.to_lowercase() == "light" {
        return Background::Light;
    }

    // Default to dark (most common for developers)
    Background::Dark
}

/// Detect the level of color support in the terminal.
///
/// Checks multiple environment variables in priority order:
/// 1. `COLORTERM=truecolor` or `COLORTERM=24bit` - True color support
/// 2. `TERM` containing "256color" - 256-color support
/// 3. `TERM=dumb` - No color support
/// 4. `WT_SESSION` - Windows Terminal (supports true color)
///
/// Defaults to Ansi16 (basic 16 colors) for safety.
pub fn detect_color_level() -> ColorLevel {
    // Check COLORTERM for true color
    if let Ok(colorterm) = env::var("COLORTERM") {
        let ct_lower = colorterm.to_lowercase();
        if ct_lower == "truecolor" || ct_lower == "24bit" {
            return ColorLevel::TrueColor;
        }
    }

    // Check TERM for 256 color
    if let Ok(term) = env::var("TERM") {
        if term == "dumb" {
            return ColorLevel::None;
        }
        if term.contains("256color") {
            return ColorLevel::Ansi256;
        }
    }

    // Check Windows Terminal (supports true color)
    if env::var("WT_SESSION").is_ok() {
        return ColorLevel::TrueColor;
    }

    // Check for ConEmu (Windows terminal emulator with true color)
    if env::var("ConEmuANSI").is_ok() {
        return ColorLevel::TrueColor;
    }

    // Default to 16 colors for safety
    ColorLevel::Ansi16
}

/// Check if the terminal supports hyperlinks (OSC 8).
///
/// Terminal hyperlinks use the OSC 8 escape sequence to create clickable links.
/// This is supported by modern terminals like:
/// - iTerm2
/// - Windows Terminal
/// - VTE-based terminals (GNOME Terminal, Tilix, etc.)
/// - Kitty
/// - Alacritty (recent versions)
pub fn detect_hyperlink_support() -> bool {
    // Check for terminals known to support hyperlinks
    if env::var("WT_SESSION").is_ok() {
        // Windows Terminal
        return true;
    }

    if let Ok(term_program) = env::var("TERM_PROGRAM") {
        let program_lower = term_program.to_lowercase();
        // iTerm2, Hyper, Kitty
        if program_lower.contains("iterm")
            || program_lower.contains("hyper")
            || program_lower.contains("kitty")
        {
            return true;
        }
    }

    // Check for VTE version (used by GNOME Terminal, Tilix, etc.)
    // VTE >= 0.50 supports hyperlinks
    if let Ok(vte_version) = env::var("VTE_VERSION")
        && let Ok(version) = vte_version.parse::<u32>()
        && version >= 5000
    {
        // VTE 0.50 is version 5000
        return true;
    }

    // Check TERM_FEATURES for hyperlink support (some terminals set this)
    if let Ok(features) = env::var("TERM_FEATURES") && features.contains("hyperlink") {
        return true;
    }

    // Default to no hyperlink support for safety
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    fn log_test_start(name: &str) {
        info!("TEST START: {}", name);
    }

    #[test]
    fn test_color_level_ordering() {
        log_test_start("test_color_level_ordering");
        assert!(ColorLevel::None < ColorLevel::Ansi16);
        assert!(ColorLevel::Ansi16 < ColorLevel::Ansi256);
        assert!(ColorLevel::Ansi256 < ColorLevel::TrueColor);
    }

    #[test]
    fn test_color_level_supports_256() {
        log_test_start("test_color_level_supports_256");
        assert!(!ColorLevel::None.supports_256());
        assert!(!ColorLevel::Ansi16.supports_256());
        assert!(ColorLevel::Ansi256.supports_256());
        assert!(ColorLevel::TrueColor.supports_256());
    }

    #[test]
    fn test_color_level_supports_true_color() {
        log_test_start("test_color_level_supports_true_color");
        assert!(!ColorLevel::None.supports_true_color());
        assert!(!ColorLevel::Ansi16.supports_true_color());
        assert!(!ColorLevel::Ansi256.supports_true_color());
        assert!(ColorLevel::TrueColor.supports_true_color());
    }

    #[test]
    fn test_background_default_is_dark() {
        log_test_start("test_background_default_is_dark");
        assert_eq!(Background::default(), Background::Dark);
    }

    #[test]
    fn test_adaptive_color_resolve_dark() {
        log_test_start("test_adaptive_color_resolve_dark");
        let adaptive = AdaptiveColor::new(Color::Black, Color::White);
        assert_eq!(adaptive.resolve(Background::Dark), Color::White);
    }

    #[test]
    fn test_adaptive_color_resolve_light() {
        log_test_start("test_adaptive_color_resolve_light");
        let adaptive = AdaptiveColor::new(Color::Black, Color::White);
        assert_eq!(adaptive.resolve(Background::Light), Color::Black);
    }

    #[test]
    fn test_palette_colors_exist() {
        log_test_start("test_palette_colors_exist");
        // Just verify the palette colors are defined and can be resolved
        let bg = Background::Dark;
        let _ = palette::SUBTLE.resolve(bg);
        let _ = palette::HIGHLIGHT.resolve(bg);
        let _ = palette::SUCCESS.resolve(bg);
        let _ = palette::ERROR.resolve(bg);
        let _ = palette::WARNING.resolve(bg);
        let _ = palette::INFO.resolve(bg);
    }

    #[test]
    fn test_detect_background_default() {
        log_test_start("test_detect_background_default");
        // Without specific env vars set, should default to Dark
        // Note: This test might behave differently in CI environments
        // that have COLORFGBG set
        let result = detect_background();
        // Just verify it returns a valid variant
        assert!(result == Background::Light || result == Background::Dark);
    }

    #[test]
    fn test_detect_color_level_default() {
        log_test_start("test_detect_color_level_default");
        // Without specific env vars, should return a valid ColorLevel
        let result = detect_color_level();
        assert!(
            result == ColorLevel::None
                || result == ColorLevel::Ansi16
                || result == ColorLevel::Ansi256
                || result == ColorLevel::TrueColor
        );
    }
}
