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
        info!("INPUT: text={:?} enter={:?} backspace={:?} esc={:?}", text, enter, backspace, esc);
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
}
