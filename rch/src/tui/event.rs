//! Event handling for the TUI.
//!
//! Handles keyboard input and terminal events using crossterm.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

/// Keyboard action from user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Quit the application.
    Quit,
    /// Move selection up.
    Up,
    /// Move selection down.
    Down,
    /// Switch to next panel.
    NextPanel,
    /// Switch to previous panel.
    PrevPanel,
    /// Select/enter on current item.
    Select,
    /// Go back/cancel.
    Back,
    /// Refresh data.
    Refresh,
    /// Toggle help overlay.
    Help,
    /// Filter input mode.
    Filter,
    /// Copy to clipboard.
    Copy,
    /// Text input character (for filter/search).
    TextInput(char),
    /// Delete last character (backspace in text mode).
    DeleteChar,
    /// Page up for scrolling.
    PageUp,
    /// Page down for scrolling.
    PageDown,
    /// Jump to top.
    JumpTop,
    /// Jump to bottom.
    JumpBottom,
    /// No action (tick).
    Tick,
}

/// Convert key event to action (normal mode).
fn handle_key(key: KeyEvent) -> Action {
    // Check for Ctrl+C to quit
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::Tab => Action::NextPanel,
        KeyCode::BackTab => Action::PrevPanel,
        KeyCode::Enter => Action::Select,
        KeyCode::Backspace => Action::Back,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('?') | KeyCode::F(1) => Action::Help,
        KeyCode::Char('/') => Action::Filter,
        KeyCode::Char('y') => Action::Copy,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Char('g') => Action::JumpTop,
        KeyCode::Char('G') => Action::JumpBottom,
        _ => Action::Tick,
    }
}

/// Convert key event to action when in text input mode (filter/search).
fn handle_key_input_mode(key: KeyEvent) -> Action {
    // Check for Ctrl+C to quit even in input mode
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Esc => Action::Back,     // Exit input mode
        KeyCode::Enter => Action::Select, // Apply filter
        KeyCode::Backspace => Action::DeleteChar,
        KeyCode::Char(c) => Action::TextInput(c),
        _ => Action::Tick,
    }
}

/// Poll for events with optional input mode flag.
pub fn poll_event_with_mode(
    timeout: Duration,
    input_mode: bool,
) -> std::io::Result<Option<Action>> {
    if event::poll(timeout)? {
        match event::read()? {
            Event::Key(key) => {
                let action = if input_mode {
                    handle_key_input_mode(key)
                } else {
                    handle_key(key)
                };
                Ok(Some(action))
            }
            Event::Resize(_, _) => Ok(Some(Action::Tick)),
            _ => Ok(None),
        }
    } else {
        Ok(Some(Action::Tick))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyEventKind};
    use tracing::info;

    fn init_test_logging() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    #[test]
    fn test_handle_key_quit_variants() {
        init_test_logging();
        info!("TEST START: test_handle_key_quit_variants");
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        info!("INPUT: ctrl_c={:?} q={:?} esc={:?}", ctrl_c, q, esc);
        assert_eq!(handle_key(ctrl_c), Action::Quit);
        assert_eq!(handle_key(q), Action::Quit);
        assert_eq!(handle_key(esc), Action::Quit);
        info!("TEST PASS: test_handle_key_quit_variants");
    }

    #[test]
    fn test_handle_key_navigation() {
        init_test_logging();
        info!("TEST START: test_handle_key_navigation");
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Action::Up
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)),
            Action::Up
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            Action::Down
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
            Action::Down
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::NextPanel
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)),
            Action::PrevPanel
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE)),
            Action::PageUp
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE)),
            Action::PageDown
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE)),
            Action::JumpTop
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT)),
            Action::JumpBottom
        );
        info!("TEST PASS: test_handle_key_navigation");
    }

    #[test]
    fn test_handle_key_actions() {
        init_test_logging();
        info!("TEST START: test_handle_key_actions");
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::Refresh
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)),
            Action::Help
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)),
            Action::Help
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE)),
            Action::Filter
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::Copy
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::Select
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)),
            Action::Back
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            Action::Tick
        );
        info!("TEST PASS: test_handle_key_actions");
    }

    #[test]
    fn test_handle_key_input_mode_text() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_text");
        let text = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        info!(
            "INPUT: text={:?} enter={:?} backspace={:?} esc={:?}",
            text, enter, backspace, esc
        );
        assert_eq!(handle_key_input_mode(text), Action::TextInput('a'));
        assert_eq!(handle_key_input_mode(enter), Action::Select);
        assert_eq!(handle_key_input_mode(backspace), Action::DeleteChar);
        assert_eq!(handle_key_input_mode(esc), Action::Back);
        info!("TEST PASS: test_handle_key_input_mode_text");
    }

    #[test]
    fn test_handle_key_input_mode_ctrl_c_quit() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_ctrl_c_quit");
        let ctrl_c = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(handle_key_input_mode(ctrl_c), Action::Quit);
        info!("TEST PASS: test_handle_key_input_mode_ctrl_c_quit");
    }

    // ==================== Normal mode modifier tests ====================

    #[test]
    fn test_handle_key_ctrl_c_quit() {
        init_test_logging();
        info!("TEST START: test_handle_key_ctrl_c_quit");
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(handle_key(ctrl_c), Action::Quit);
        info!("TEST PASS: test_handle_key_ctrl_c_quit");
    }

    #[test]
    fn test_handle_key_shift_g_jump_bottom() {
        init_test_logging();
        info!("TEST START: test_handle_key_shift_g_jump_bottom");
        // Capital G (shift+g) should jump to bottom
        let shift_g = KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT);
        assert_eq!(handle_key(shift_g), Action::JumpBottom);
        info!("TEST PASS: test_handle_key_shift_g_jump_bottom");
    }

    #[test]
    fn test_handle_key_lowercase_g_jump_top() {
        init_test_logging();
        info!("TEST START: test_handle_key_lowercase_g_jump_top");
        let g = KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE);
        assert_eq!(handle_key(g), Action::JumpTop);
        info!("TEST PASS: test_handle_key_lowercase_g_jump_top");
    }

    // ==================== Function key tests ====================

    #[test]
    fn test_handle_key_f1_help() {
        init_test_logging();
        info!("TEST START: test_handle_key_f1_help");
        let f1 = KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE);
        assert_eq!(handle_key(f1), Action::Help);
        info!("TEST PASS: test_handle_key_f1_help");
    }

    #[test]
    fn test_handle_key_other_function_keys_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_other_function_keys_tick");
        // F2-F12 should be Tick (no action)
        for i in 2..=12 {
            let f_key = KeyEvent::new(KeyCode::F(i), KeyModifiers::NONE);
            assert_eq!(
                handle_key(f_key),
                Action::Tick,
                "F{} should be Tick",
                i
            );
        }
        info!("TEST PASS: test_handle_key_other_function_keys_tick");
    }

    // ==================== Vim-style navigation tests ====================

    #[test]
    fn test_handle_key_vim_j_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_j_down");
        let j = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(handle_key(j), Action::Down);
        info!("TEST PASS: test_handle_key_vim_j_down");
    }

    #[test]
    fn test_handle_key_vim_k_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_k_up");
        let k = KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE);
        assert_eq!(handle_key(k), Action::Up);
        info!("TEST PASS: test_handle_key_vim_k_up");
    }

    // ==================== Arrow key navigation tests ====================

    #[test]
    fn test_handle_key_arrow_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_arrow_up");
        let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(handle_key(up), Action::Up);
        info!("TEST PASS: test_handle_key_arrow_up");
    }

    #[test]
    fn test_handle_key_arrow_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_arrow_down");
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(handle_key(down), Action::Down);
        info!("TEST PASS: test_handle_key_arrow_down");
    }

    // ==================== Tab navigation tests ====================

    #[test]
    fn test_handle_key_tab_next_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_tab_next_panel");
        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(handle_key(tab), Action::NextPanel);
        info!("TEST PASS: test_handle_key_tab_next_panel");
    }

    #[test]
    fn test_handle_key_backtab_prev_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_backtab_prev_panel");
        let backtab = KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE);
        assert_eq!(handle_key(backtab), Action::PrevPanel);
        info!("TEST PASS: test_handle_key_backtab_prev_panel");
    }

    // ==================== Action key tests ====================

    #[test]
    fn test_handle_key_slash_filter() {
        init_test_logging();
        info!("TEST START: test_handle_key_slash_filter");
        let slash = KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE);
        assert_eq!(handle_key(slash), Action::Filter);
        info!("TEST PASS: test_handle_key_slash_filter");
    }

    #[test]
    fn test_handle_key_y_copy() {
        init_test_logging();
        info!("TEST START: test_handle_key_y_copy");
        let y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE);
        assert_eq!(handle_key(y), Action::Copy);
        info!("TEST PASS: test_handle_key_y_copy");
    }

    #[test]
    fn test_handle_key_r_refresh() {
        init_test_logging();
        info!("TEST START: test_handle_key_r_refresh");
        let r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE);
        assert_eq!(handle_key(r), Action::Refresh);
        info!("TEST PASS: test_handle_key_r_refresh");
    }

    #[test]
    fn test_handle_key_enter_select() {
        init_test_logging();
        info!("TEST START: test_handle_key_enter_select");
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(handle_key(enter), Action::Select);
        info!("TEST PASS: test_handle_key_enter_select");
    }

    #[test]
    fn test_handle_key_backspace_back() {
        init_test_logging();
        info!("TEST START: test_handle_key_backspace_back");
        let backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(handle_key(backspace), Action::Back);
        info!("TEST PASS: test_handle_key_backspace_back");
    }

    #[test]
    fn test_handle_key_question_mark_help() {
        init_test_logging();
        info!("TEST START: test_handle_key_question_mark_help");
        let qmark = KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE);
        assert_eq!(handle_key(qmark), Action::Help);
        info!("TEST PASS: test_handle_key_question_mark_help");
    }

    // ==================== Input mode text entry tests ====================

    #[test]
    fn test_handle_key_input_mode_letters() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_letters");
        for c in 'a'..='z' {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
            assert_eq!(handle_key_input_mode(key), Action::TextInput(c));
        }
        info!("TEST PASS: test_handle_key_input_mode_letters");
    }

    #[test]
    fn test_handle_key_input_mode_numbers() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_numbers");
        for c in '0'..='9' {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
            assert_eq!(handle_key_input_mode(key), Action::TextInput(c));
        }
        info!("TEST PASS: test_handle_key_input_mode_numbers");
    }

    #[test]
    fn test_handle_key_input_mode_special_chars() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_special_chars");
        let specials = ['!', '@', '#', '$', '%', '^', '&', '*', '-', '_', '.'];
        for c in specials {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
            assert_eq!(handle_key_input_mode(key), Action::TextInput(c));
        }
        info!("TEST PASS: test_handle_key_input_mode_special_chars");
    }

    #[test]
    fn test_handle_key_input_mode_backspace_delete_char() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_backspace_delete_char");
        let backspace = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(handle_key_input_mode(backspace), Action::DeleteChar);
        info!("TEST PASS: test_handle_key_input_mode_backspace_delete_char");
    }

    #[test]
    fn test_handle_key_input_mode_esc_back() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_esc_back");
        let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(handle_key_input_mode(esc), Action::Back);
        info!("TEST PASS: test_handle_key_input_mode_esc_back");
    }

    #[test]
    fn test_handle_key_input_mode_enter_select() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_enter_select");
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(handle_key_input_mode(enter), Action::Select);
        info!("TEST PASS: test_handle_key_input_mode_enter_select");
    }

    #[test]
    fn test_handle_key_input_mode_unknown_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_unknown_tick");
        // Arrow keys in input mode should be Tick (no action)
        let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(handle_key_input_mode(up), Action::Tick);
        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(handle_key_input_mode(down), Action::Tick);
        info!("TEST PASS: test_handle_key_input_mode_unknown_tick");
    }

    // ==================== Page navigation tests ====================

    #[test]
    fn test_handle_key_page_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_page_up");
        let pgup = KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE);
        assert_eq!(handle_key(pgup), Action::PageUp);
        info!("TEST PASS: test_handle_key_page_up");
    }

    #[test]
    fn test_handle_key_page_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_page_down");
        let pgdn = KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(handle_key(pgdn), Action::PageDown);
        info!("TEST PASS: test_handle_key_page_down");
    }

    // ==================== Action enum tests ====================

    #[test]
    fn test_action_enum_equality() {
        init_test_logging();
        info!("TEST START: test_action_enum_equality");
        assert_eq!(Action::Quit, Action::Quit);
        assert_eq!(Action::Up, Action::Up);
        assert_eq!(Action::Down, Action::Down);
        assert_eq!(Action::TextInput('a'), Action::TextInput('a'));
        assert_ne!(Action::TextInput('a'), Action::TextInput('b'));
        assert_ne!(Action::Quit, Action::Tick);
        info!("TEST PASS: test_action_enum_equality");
    }

    #[test]
    fn test_action_enum_clone() {
        init_test_logging();
        info!("TEST START: test_action_enum_clone");
        let original = Action::TextInput('x');
        let cloned = original.clone();
        assert_eq!(original, cloned);
        info!("TEST PASS: test_action_enum_clone");
    }

    #[test]
    fn test_action_enum_debug() {
        init_test_logging();
        info!("TEST START: test_action_enum_debug");
        let action = Action::Quit;
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("Quit"));
        info!("TEST PASS: test_action_enum_debug");
    }

    // ==================== Unknown key tests ====================

    #[test]
    fn test_handle_key_unknown_char_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_unknown_char_tick");
        // Characters that aren't mapped should return Tick
        let z = KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE);
        assert_eq!(handle_key(z), Action::Tick);
        let x = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(handle_key(x), Action::Tick);
        info!("TEST PASS: test_handle_key_unknown_char_tick");
    }

    #[test]
    fn test_handle_key_home_end_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_home_end_tick");
        // Home and End keys are not mapped
        let home = KeyEvent::new(KeyCode::Home, KeyModifiers::NONE);
        assert_eq!(handle_key(home), Action::Tick);
        let end = KeyEvent::new(KeyCode::End, KeyModifiers::NONE);
        assert_eq!(handle_key(end), Action::Tick);
        info!("TEST PASS: test_handle_key_home_end_tick");
    }
}
