//! Icons with automatic Unicode/ASCII fallback for terminals.
//!
//! Provides Unicode icons for modern terminals with ASCII fallbacks
//! for environments that don't support Unicode (CI, older terminals, etc.).

use super::OutputContext;

/// Icons with automatic fallback for non-Unicode terminals.
///
/// All icon methods take an `OutputContext` to determine whether to return
/// Unicode characters or ASCII fallbacks.
///
/// # Example
///
/// ```ignore
/// use rch_common::ui::{Icons, OutputContext};
///
/// let ctx = OutputContext::detect();
/// println!("{} Build successful", Icons::check(ctx));
/// ```
pub struct Icons;

impl Icons {
    // ═══════════════════════════════════════════════════════════════════════
    // STATUS INDICATORS
    // ═══════════════════════════════════════════════════════════════════════

    /// Success indicator (check mark).
    #[must_use]
    pub fn check(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2713}" // ✓
        } else {
            "[OK]"
        }
    }

    /// Failure indicator (cross mark).
    #[must_use]
    pub fn cross(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2717}" // ✗
        } else {
            "[FAIL]"
        }
    }

    /// Warning indicator.
    #[must_use]
    pub fn warning(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{26A0}" // ⚠
        } else {
            "[WARN]"
        }
    }

    /// Info indicator.
    #[must_use]
    pub fn info(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2139}" // ℹ
        } else {
            "[INFO]"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORKER STATUS (filled circle variants)
    // ═══════════════════════════════════════════════════════════════════════

    /// Healthy worker (filled circle).
    #[must_use]
    pub fn status_healthy(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25CF}" // ●
        } else {
            "[*]"
        }
    }

    /// Degraded worker (half-filled circle).
    #[must_use]
    pub fn status_degraded(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25D0}" // ◐
        } else {
            "[~]"
        }
    }

    /// Unreachable worker (empty circle).
    #[must_use]
    pub fn status_unreachable(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25CB}" // ○
        } else {
            "[ ]"
        }
    }

    /// Draining worker (quarter circle).
    #[must_use]
    pub fn status_draining(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25D1}" // ◑
        } else {
            "[/]"
        }
    }

    /// Disabled worker (dotted circle).
    #[must_use]
    pub fn status_disabled(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25CC}" // ◌
        } else {
            "[x]"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARROWS AND DIRECTION
    // ═══════════════════════════════════════════════════════════════════════

    /// Right arrow (for flow, assignment).
    #[must_use]
    pub fn arrow_right(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2192}" // →
        } else {
            "->"
        }
    }

    /// Left arrow.
    #[must_use]
    pub fn arrow_left(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2190}" // ←
        } else {
            "<-"
        }
    }

    /// Up arrow (for upload).
    #[must_use]
    pub fn arrow_up(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2191}" // ↑
        } else {
            "^"
        }
    }

    /// Down arrow (for download).
    #[must_use]
    pub fn arrow_down(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2193}" // ↓
        } else {
            "v"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LIST AND BULLET
    // ═══════════════════════════════════════════════════════════════════════

    /// Bullet point.
    #[must_use]
    pub fn bullet(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2022}" // •
        } else {
            "*"
        }
    }

    /// Secondary/hollow bullet.
    #[must_use]
    pub fn bullet_hollow(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{25CB}" // ○
        } else {
            "o"
        }
    }

    /// Tree branch connector.
    #[must_use]
    pub fn tree_branch(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{251C}" // ├
        } else {
            "|"
        }
    }

    /// Tree end connector.
    #[must_use]
    pub fn tree_end(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2514}" // └
        } else {
            "`"
        }
    }

    /// Tree vertical line.
    #[must_use]
    pub fn tree_vertical(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2502}" // │
        } else {
            "|"
        }
    }

    /// Tree horizontal line.
    #[must_use]
    pub fn tree_horizontal(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2500}" // ─
        } else {
            "-"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACTIVITY AND PROCESS
    // ═══════════════════════════════════════════════════════════════════════

    /// Worker/computer icon.
    #[must_use]
    pub fn worker(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{1F5A5}" // 🖥
        } else {
            "[W]"
        }
    }

    /// Compilation/build icon (hammer).
    #[must_use]
    pub fn compile(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{1F528}" // 🔨
        } else {
            "[C]"
        }
    }

    /// Transfer/package icon.
    #[must_use]
    pub fn transfer(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{1F4E6}" // 📦
        } else {
            "[T]"
        }
    }

    /// Clock/time icon.
    #[must_use]
    pub fn clock(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{23F1}" // ⏱
        } else {
            "[T]"
        }
    }

    /// Gear/settings icon.
    #[must_use]
    pub fn gear(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2699}" // ⚙
        } else {
            "[G]"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SLOT VISUALIZATION (for worker slots)
    // ═══════════════════════════════════════════════════════════════════════

    /// Filled slot (in use).
    #[must_use]
    pub fn slot_filled(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2588}" // █
        } else {
            "#"
        }
    }

    /// Empty slot (available).
    #[must_use]
    pub fn slot_empty(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2591}" // ░
        } else {
            "-"
        }
    }

    /// Partial slot (for progress).
    #[must_use]
    pub fn slot_partial(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2593}" // ▓
        } else {
            "="
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PROGRESS BAR CHARACTERS
    // ═══════════════════════════════════════════════════════════════════════

    /// Progress bar filled segment.
    #[must_use]
    pub fn progress_filled(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2501}" // ━
        } else {
            "="
        }
    }

    /// Progress bar empty segment.
    #[must_use]
    pub fn progress_empty(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2500}" // ─
        } else {
            "-"
        }
    }

    /// Progress bar head/cursor.
    #[must_use]
    pub fn progress_head(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{2578}" // ╸
        } else {
            ">"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MISCELLANEOUS
    // ═══════════════════════════════════════════════════════════════════════

    /// Lightning bolt (for speed).
    #[must_use]
    pub fn lightning(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{26A1}" // ⚡
        } else {
            "!"
        }
    }

    /// Light bulb (for tips/suggestions).
    #[must_use]
    pub fn lightbulb(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{1F4A1}" // 💡
        } else {
            "TIP:"
        }
    }

    /// Lock (for reserved/locked).
    #[must_use]
    pub fn lock(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{1F512}" // 🔒
        } else {
            "[L]"
        }
    }

    /// Hourglass (for waiting/pending).
    #[must_use]
    pub fn hourglass(ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            "\u{231B}" // ⌛
        } else {
            "[...]"
        }
    }

    /// Spinner frames for animation (returns array of frames).
    #[must_use]
    pub fn spinner_frames(ctx: OutputContext) -> &'static [&'static str] {
        if ctx.supports_unicode() {
            &[
                "\u{280B}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283C}", "\u{2834}", "\u{2826}",
                "\u{2827}", "\u{2807}", "\u{280F}",
            ]
            // ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ (braille spinner)
        } else {
            &["|", "/", "-", "\\"]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_icons_return_non_empty_unicode() {
        let ctx = OutputContext::Interactive;

        // All icon methods should return non-empty strings
        assert!(!Icons::check(ctx).is_empty());
        assert!(!Icons::cross(ctx).is_empty());
        assert!(!Icons::warning(ctx).is_empty());
        assert!(!Icons::info(ctx).is_empty());
        assert!(!Icons::status_healthy(ctx).is_empty());
        assert!(!Icons::status_degraded(ctx).is_empty());
        assert!(!Icons::status_unreachable(ctx).is_empty());
        assert!(!Icons::status_draining(ctx).is_empty());
        assert!(!Icons::status_disabled(ctx).is_empty());
        assert!(!Icons::arrow_right(ctx).is_empty());
        assert!(!Icons::arrow_left(ctx).is_empty());
        assert!(!Icons::arrow_up(ctx).is_empty());
        assert!(!Icons::arrow_down(ctx).is_empty());
        assert!(!Icons::bullet(ctx).is_empty());
        assert!(!Icons::bullet_hollow(ctx).is_empty());
        assert!(!Icons::tree_branch(ctx).is_empty());
        assert!(!Icons::tree_end(ctx).is_empty());
        assert!(!Icons::tree_vertical(ctx).is_empty());
        assert!(!Icons::tree_horizontal(ctx).is_empty());
        assert!(!Icons::worker(ctx).is_empty());
        assert!(!Icons::compile(ctx).is_empty());
        assert!(!Icons::transfer(ctx).is_empty());
        assert!(!Icons::clock(ctx).is_empty());
        assert!(!Icons::gear(ctx).is_empty());
        assert!(!Icons::slot_filled(ctx).is_empty());
        assert!(!Icons::slot_empty(ctx).is_empty());
        assert!(!Icons::slot_partial(ctx).is_empty());
        assert!(!Icons::progress_filled(ctx).is_empty());
        assert!(!Icons::progress_empty(ctx).is_empty());
        assert!(!Icons::progress_head(ctx).is_empty());
        assert!(!Icons::lightning(ctx).is_empty());
        assert!(!Icons::lightbulb(ctx).is_empty());
        assert!(!Icons::lock(ctx).is_empty());
        assert!(!Icons::hourglass(ctx).is_empty());
    }

    #[test]
    fn test_all_icons_return_ascii_fallbacks() {
        let ctx = OutputContext::Plain;

        // All fallbacks should be pure ASCII
        assert!(Icons::check(ctx).is_ascii());
        assert!(Icons::cross(ctx).is_ascii());
        assert!(Icons::warning(ctx).is_ascii());
        assert!(Icons::info(ctx).is_ascii());
        assert!(Icons::status_healthy(ctx).is_ascii());
        assert!(Icons::status_degraded(ctx).is_ascii());
        assert!(Icons::status_unreachable(ctx).is_ascii());
        assert!(Icons::status_draining(ctx).is_ascii());
        assert!(Icons::status_disabled(ctx).is_ascii());
        assert!(Icons::arrow_right(ctx).is_ascii());
        assert!(Icons::arrow_left(ctx).is_ascii());
        assert!(Icons::arrow_up(ctx).is_ascii());
        assert!(Icons::arrow_down(ctx).is_ascii());
        assert!(Icons::bullet(ctx).is_ascii());
        assert!(Icons::bullet_hollow(ctx).is_ascii());
        assert!(Icons::tree_branch(ctx).is_ascii());
        assert!(Icons::tree_end(ctx).is_ascii());
        assert!(Icons::tree_vertical(ctx).is_ascii());
        assert!(Icons::tree_horizontal(ctx).is_ascii());
        assert!(Icons::worker(ctx).is_ascii());
        assert!(Icons::compile(ctx).is_ascii());
        assert!(Icons::transfer(ctx).is_ascii());
        assert!(Icons::clock(ctx).is_ascii());
        assert!(Icons::gear(ctx).is_ascii());
        assert!(Icons::slot_filled(ctx).is_ascii());
        assert!(Icons::slot_empty(ctx).is_ascii());
        assert!(Icons::slot_partial(ctx).is_ascii());
        assert!(Icons::progress_filled(ctx).is_ascii());
        assert!(Icons::progress_empty(ctx).is_ascii());
        assert!(Icons::progress_head(ctx).is_ascii());
        assert!(Icons::lightning(ctx).is_ascii());
        assert!(Icons::lightbulb(ctx).is_ascii());
        assert!(Icons::lock(ctx).is_ascii());
        assert!(Icons::hourglass(ctx).is_ascii());
    }

    #[test]
    fn test_spinner_frames() {
        let unicode_frames = Icons::spinner_frames(OutputContext::Interactive);
        let ascii_frames = Icons::spinner_frames(OutputContext::Plain);

        // Both should have multiple frames
        assert!(unicode_frames.len() >= 4);
        assert!(ascii_frames.len() >= 4);

        // ASCII frames should all be ASCII
        for frame in ascii_frames {
            assert!(frame.is_ascii());
        }
    }

    #[test]
    fn test_hook_mode_uses_ascii() {
        let ctx = OutputContext::Hook;

        // Hook mode should use ASCII fallbacks (no unicode support)
        assert!(Icons::check(ctx).is_ascii());
        assert!(Icons::cross(ctx).is_ascii());
    }

    #[test]
    fn test_machine_mode_uses_ascii() {
        let ctx = OutputContext::Machine;

        // Machine mode should use ASCII fallbacks (no unicode support)
        assert!(Icons::check(ctx).is_ascii());
        assert!(Icons::cross(ctx).is_ascii());
    }

    #[test]
    fn test_status_icons_are_distinct() {
        let ctx = OutputContext::Plain;

        // All worker status icons should be visually distinct
        let healthy = Icons::status_healthy(ctx);
        let degraded = Icons::status_degraded(ctx);
        let unreachable = Icons::status_unreachable(ctx);
        let draining = Icons::status_draining(ctx);
        let disabled = Icons::status_disabled(ctx);

        assert_ne!(healthy, degraded);
        assert_ne!(healthy, unreachable);
        assert_ne!(healthy, draining);
        assert_ne!(healthy, disabled);
        assert_ne!(degraded, unreachable);
        assert_ne!(degraded, draining);
        assert_ne!(degraded, disabled);
        assert_ne!(unreachable, draining);
        assert_ne!(unreachable, disabled);
        assert_ne!(draining, disabled);
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_unicode_icons_are_not_ascii() {
        let ctx = OutputContext::Interactive;

        // Unicode mode should use actual Unicode characters (not ASCII)
        assert!(!Icons::check(ctx).is_ascii());
        assert!(!Icons::cross(ctx).is_ascii());
        assert!(!Icons::warning(ctx).is_ascii());
        assert!(!Icons::info(ctx).is_ascii());
        assert!(!Icons::status_healthy(ctx).is_ascii());
        assert!(!Icons::status_degraded(ctx).is_ascii());
        assert!(!Icons::status_unreachable(ctx).is_ascii());
    }

    #[test]
    fn test_arrow_icons_are_distinct() {
        let ctx = OutputContext::Plain;

        let right = Icons::arrow_right(ctx);
        let left = Icons::arrow_left(ctx);
        let up = Icons::arrow_up(ctx);
        let down = Icons::arrow_down(ctx);

        assert_ne!(right, left);
        assert_ne!(right, up);
        assert_ne!(right, down);
        assert_ne!(left, up);
        assert_ne!(left, down);
        assert_ne!(up, down);
    }

    #[test]
    fn test_arrow_icons_unicode_distinct() {
        let ctx = OutputContext::Interactive;

        let right = Icons::arrow_right(ctx);
        let left = Icons::arrow_left(ctx);
        let up = Icons::arrow_up(ctx);
        let down = Icons::arrow_down(ctx);

        assert_ne!(right, left);
        assert_ne!(right, up);
        assert_ne!(right, down);
        assert_ne!(left, up);
        assert_ne!(left, down);
        assert_ne!(up, down);
    }

    #[test]
    fn test_tree_icons_are_distinct() {
        let ctx = OutputContext::Plain;

        let branch = Icons::tree_branch(ctx);
        let end = Icons::tree_end(ctx);
        let vertical = Icons::tree_vertical(ctx);
        let horizontal = Icons::tree_horizontal(ctx);

        // At least some should be distinct
        assert_ne!(branch, end);
        assert_ne!(end, horizontal);
        assert_ne!(vertical, horizontal);
    }

    #[test]
    fn test_slot_icons_are_distinct() {
        let ctx = OutputContext::Plain;

        let filled = Icons::slot_filled(ctx);
        let empty = Icons::slot_empty(ctx);
        let partial = Icons::slot_partial(ctx);

        assert_ne!(filled, empty);
        assert_ne!(filled, partial);
        assert_ne!(empty, partial);
    }

    #[test]
    fn test_progress_icons_are_distinct() {
        let ctx = OutputContext::Plain;

        let filled = Icons::progress_filled(ctx);
        let empty = Icons::progress_empty(ctx);
        let head = Icons::progress_head(ctx);

        assert_ne!(filled, empty);
        assert_ne!(filled, head);
        assert_ne!(empty, head);
    }

    #[test]
    fn test_bullet_icons() {
        let unicode_ctx = OutputContext::Interactive;
        let ascii_ctx = OutputContext::Plain;

        // Unicode bullets should not be ASCII
        assert!(!Icons::bullet(unicode_ctx).is_ascii());

        // ASCII bullets should be simple
        assert!(Icons::bullet(ascii_ctx).is_ascii());
        assert_eq!(Icons::bullet(ascii_ctx), "*");

        // Hollow bullet should be 'o' in ASCII
        assert_eq!(Icons::bullet_hollow(ascii_ctx), "o");
    }

    #[test]
    fn test_check_specific_values() {
        // Verify specific expected values
        assert_eq!(Icons::check(OutputContext::Plain), "[OK]");
        assert_eq!(Icons::cross(OutputContext::Plain), "[FAIL]");
        assert_eq!(Icons::warning(OutputContext::Plain), "[WARN]");
        assert_eq!(Icons::info(OutputContext::Plain), "[INFO]");
    }

    #[test]
    fn test_status_specific_values() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::status_healthy(ctx), "[*]");
        assert_eq!(Icons::status_degraded(ctx), "[~]");
        assert_eq!(Icons::status_unreachable(ctx), "[ ]");
        assert_eq!(Icons::status_draining(ctx), "[/]");
        assert_eq!(Icons::status_disabled(ctx), "[x]");
    }

    #[test]
    fn test_arrow_specific_values() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::arrow_right(ctx), "->");
        assert_eq!(Icons::arrow_left(ctx), "<-");
        assert_eq!(Icons::arrow_up(ctx), "^");
        assert_eq!(Icons::arrow_down(ctx), "v");
    }

    #[test]
    fn test_tree_specific_values() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::tree_branch(ctx), "|");
        assert_eq!(Icons::tree_end(ctx), "`");
        assert_eq!(Icons::tree_vertical(ctx), "|");
        assert_eq!(Icons::tree_horizontal(ctx), "-");
    }

    #[test]
    fn test_activity_icons() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::worker(ctx), "[W]");
        assert_eq!(Icons::compile(ctx), "[C]");
        assert_eq!(Icons::transfer(ctx), "[T]");
        assert_eq!(Icons::clock(ctx), "[T]");
        assert_eq!(Icons::gear(ctx), "[G]");
    }

    #[test]
    fn test_slot_specific_values() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::slot_filled(ctx), "#");
        assert_eq!(Icons::slot_empty(ctx), "-");
        assert_eq!(Icons::slot_partial(ctx), "=");
    }

    #[test]
    fn test_progress_specific_values() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::progress_filled(ctx), "=");
        assert_eq!(Icons::progress_empty(ctx), "-");
        assert_eq!(Icons::progress_head(ctx), ">");
    }

    #[test]
    fn test_misc_icons() {
        let ctx = OutputContext::Plain;

        assert_eq!(Icons::lightning(ctx), "!");
        assert_eq!(Icons::lightbulb(ctx), "TIP:");
        assert_eq!(Icons::lock(ctx), "[L]");
        assert_eq!(Icons::hourglass(ctx), "[...]");
    }

    #[test]
    fn test_spinner_frames_ascii_values() {
        let frames = Icons::spinner_frames(OutputContext::Plain);

        assert_eq!(frames, &["|", "/", "-", "\\"]);
    }

    #[test]
    fn test_spinner_frames_unicode_count() {
        let frames = Icons::spinner_frames(OutputContext::Interactive);

        // Unicode spinner should have 10 braille frames
        assert_eq!(frames.len(), 10);

        // Each frame should be a single character
        for frame in frames {
            assert_eq!(frame.chars().count(), 1);
        }
    }

    #[test]
    fn test_plain_mode_uses_ascii() {
        let ctx = OutputContext::Plain;

        // Plain mode should use ASCII fallbacks
        assert!(Icons::check(ctx).is_ascii());
        assert!(Icons::cross(ctx).is_ascii());
        assert!(Icons::warning(ctx).is_ascii());
    }

    #[test]
    fn test_interactive_unicode_characters() {
        let ctx = OutputContext::Interactive;

        // Verify specific Unicode code points
        assert_eq!(Icons::check(ctx), "\u{2713}"); // ✓
        assert_eq!(Icons::cross(ctx), "\u{2717}"); // ✗
        assert_eq!(Icons::warning(ctx), "\u{26A0}"); // ⚠
        assert_eq!(Icons::info(ctx), "\u{2139}"); // ℹ
    }

    #[test]
    fn test_status_unicode_characters() {
        let ctx = OutputContext::Interactive;

        assert_eq!(Icons::status_healthy(ctx), "\u{25CF}"); // ●
        assert_eq!(Icons::status_degraded(ctx), "\u{25D0}"); // ◐
        assert_eq!(Icons::status_unreachable(ctx), "\u{25CB}"); // ○
        assert_eq!(Icons::status_draining(ctx), "\u{25D1}"); // ◑
        assert_eq!(Icons::status_disabled(ctx), "\u{25CC}"); // ◌
    }

    #[test]
    fn test_arrow_unicode_characters() {
        let ctx = OutputContext::Interactive;

        assert_eq!(Icons::arrow_right(ctx), "\u{2192}"); // →
        assert_eq!(Icons::arrow_left(ctx), "\u{2190}"); // ←
        assert_eq!(Icons::arrow_up(ctx), "\u{2191}"); // ↑
        assert_eq!(Icons::arrow_down(ctx), "\u{2193}"); // ↓
    }

    #[test]
    fn test_icons_consistency_across_contexts() {
        // Same icon type should have consistent semantics across contexts
        // (e.g., check is always "success", cross is always "failure")

        let contexts = [
            OutputContext::Interactive,
            OutputContext::Plain,
            OutputContext::Colored,
            OutputContext::Hook,
            OutputContext::Machine,
        ];

        for ctx in contexts {
            // All should return non-empty
            assert!(!Icons::check(ctx).is_empty());
            assert!(!Icons::cross(ctx).is_empty());
            assert!(!Icons::warning(ctx).is_empty());
        }
    }
}
