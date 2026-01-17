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
