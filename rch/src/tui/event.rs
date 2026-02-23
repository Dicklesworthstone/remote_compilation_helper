//! Event handling for the TUI.
//!
//! Handles keyboard input and terminal events using ftui-tty native backend.

use ftui::KeyCode;
use ftui_backend::BackendEventSource;
use ftui_core::event::{Event, KeyEvent, Modifiers};
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
    /// Drain the selected worker.
    DrainWorker,
    /// Enable/undrain the selected worker.
    EnableWorker,
    /// Drain all workers (with confirmation).
    DrainAllWorkers,
    /// Enable all workers.
    EnableAllWorkers,
    /// Cancel the selected build (SIGTERM, with confirmation).
    CancelBuild,
    /// Force kill the selected build (SIGKILL, with confirmation).
    ForceKillBuild,
    /// Confirm a pending action in the confirmation dialog.
    Confirm,
    /// Dismiss a pending confirmation dialog.
    Dismiss,
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
    /// Jump to a specific panel by index (0=Workers, 1=ActiveBuilds, 2=BuildHistory, 3=Logs).
    JumpToPanel(u8),
    /// Cycle sort order (build history panel).
    SortCycle,
    /// Reverse sort direction (build history panel).
    SortReverse,
    /// No action (tick).
    Tick,
}

/// Convert key event to action (normal mode).
fn handle_key(key: KeyEvent) -> Action {
    // Check for Ctrl+C to quit
    if key.modifiers.contains(Modifiers::CTRL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Escape => Action::Quit,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => Action::NextPanel,
        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => Action::PrevPanel,
        KeyCode::Enter => Action::Select,
        KeyCode::Backspace => Action::Back,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('?') | KeyCode::F(1) => Action::Help,
        KeyCode::Char('/') => Action::Filter,
        KeyCode::Char('y') => Action::Copy,
        KeyCode::Char('d') => Action::DrainWorker,
        KeyCode::Char('e') => Action::EnableWorker,
        KeyCode::Char('D') => Action::DrainAllWorkers,
        KeyCode::Char('E') => Action::EnableAllWorkers,
        KeyCode::Char('x') => Action::CancelBuild,
        KeyCode::Char('X') => Action::ForceKillBuild,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::Char('g') => Action::JumpTop,
        KeyCode::Char('G') => Action::JumpBottom,
        KeyCode::Char('H') => Action::JumpToPanel(0),
        KeyCode::Char('L') => Action::JumpToPanel(3),
        KeyCode::Char('1') => Action::JumpToPanel(0),
        KeyCode::Char('2') => Action::JumpToPanel(1),
        KeyCode::Char('3') => Action::JumpToPanel(2),
        KeyCode::Char('4') => Action::JumpToPanel(3),
        KeyCode::Char('s') => Action::SortCycle,
        KeyCode::Char('S') => Action::SortReverse,
        _ => Action::Tick,
    }
}

/// Convert key event to action when a confirmation dialog is showing.
fn handle_confirm_key(key: KeyEvent) -> Action {
    if key.modifiers.contains(Modifiers::CTRL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Action::Confirm,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Escape => Action::Dismiss,
        _ => Action::Tick,
    }
}

/// Convert key event to action when in text input mode (filter/search).
fn handle_key_input_mode(key: KeyEvent) -> Action {
    // Check for Ctrl+C to quit even in input mode
    if key.modifiers.contains(Modifiers::CTRL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Escape => Action::Back,     // Exit input mode
        KeyCode::Enter => Action::Select, // Apply filter
        KeyCode::Backspace => Action::DeleteChar,
        KeyCode::Char(c) => Action::TextInput(c),
        _ => Action::Tick,
    }
}

/// Poll for events with input mode and confirm dialog flags.
pub fn poll_event_with_flags(
    events: &mut impl BackendEventSource<Error = std::io::Error>,
    timeout: Duration,
    input_mode: bool,
    confirm_mode: bool,
) -> std::io::Result<Option<Action>> {
    if events.poll_event(timeout)? {
        if let Some(ev) = events.read_event()? {
            match ev {
                Event::Key(key) => {
                    let action = if confirm_mode {
                        handle_confirm_key(key)
                    } else if input_mode {
                        handle_key_input_mode(key)
                    } else {
                        handle_key(key)
                    };
                    Ok(Some(action))
                }
                Event::Resize { .. } => Ok(Some(Action::Tick)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    } else {
        Ok(Some(Action::Tick))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ftui_core::event::{KeyEvent, KeyEventKind};
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
        let ctrl_c = KeyEvent::new(KeyCode::Char('c')).with_modifiers(Modifiers::CTRL);
        let q = KeyEvent::new(KeyCode::Char('q'));
        let esc = KeyEvent::new(KeyCode::Escape);
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
            handle_key(KeyEvent::new(KeyCode::Up)),
            Action::Up
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('k'))),
            Action::Up
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Down)),
            Action::Down
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('j'))),
            Action::Down
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Tab)),
            Action::NextPanel
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::BackTab)),
            Action::PrevPanel
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::PageUp)),
            Action::PageUp
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::PageDown)),
            Action::PageDown
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('g'))),
            Action::JumpTop
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('G')).with_modifiers(Modifiers::SHIFT)),
            Action::JumpBottom
        );
        info!("TEST PASS: test_handle_key_navigation");
    }

    #[test]
    fn test_handle_key_actions() {
        init_test_logging();
        info!("TEST START: test_handle_key_actions");
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('r'))),
            Action::Refresh
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('?'))),
            Action::Help
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::F(1))),
            Action::Help
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('/'))),
            Action::Filter
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('y'))),
            Action::Copy
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Enter)),
            Action::Select
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Backspace)),
            Action::Back
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('x'))),
            Action::CancelBuild
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('X'))),
            Action::ForceKillBuild
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('D'))),
            Action::DrainAllWorkers
        );
        assert_eq!(
            handle_key(KeyEvent::new(KeyCode::Char('E'))),
            Action::EnableAllWorkers
        );
        info!("TEST PASS: test_handle_key_actions");
    }

    #[test]
    fn test_handle_key_input_mode_text() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_text");
        let text = KeyEvent::new(KeyCode::Char('a'));
        let enter = KeyEvent::new(KeyCode::Enter);
        let backspace = KeyEvent::new(KeyCode::Backspace);
        let esc = KeyEvent::new(KeyCode::Escape);
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
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'))
            .with_modifiers(Modifiers::CTRL)
            .with_kind(KeyEventKind::Press);
        assert_eq!(handle_key_input_mode(ctrl_c), Action::Quit);
        info!("TEST PASS: test_handle_key_input_mode_ctrl_c_quit");
    }

    // ==================== Normal mode modifier tests ====================

    #[test]
    fn test_handle_key_ctrl_c_quit() {
        init_test_logging();
        info!("TEST START: test_handle_key_ctrl_c_quit");
        let ctrl_c = KeyEvent::new(KeyCode::Char('c')).with_modifiers(Modifiers::CTRL);
        assert_eq!(handle_key(ctrl_c), Action::Quit);
        info!("TEST PASS: test_handle_key_ctrl_c_quit");
    }

    #[test]
    fn test_handle_key_shift_g_jump_bottom() {
        init_test_logging();
        info!("TEST START: test_handle_key_shift_g_jump_bottom");
        // Capital G (shift+g) should jump to bottom
        let shift_g = KeyEvent::new(KeyCode::Char('G')).with_modifiers(Modifiers::SHIFT);
        assert_eq!(handle_key(shift_g), Action::JumpBottom);
        info!("TEST PASS: test_handle_key_shift_g_jump_bottom");
    }

    #[test]
    fn test_handle_key_lowercase_g_jump_top() {
        init_test_logging();
        info!("TEST START: test_handle_key_lowercase_g_jump_top");
        let g = KeyEvent::new(KeyCode::Char('g'));
        assert_eq!(handle_key(g), Action::JumpTop);
        info!("TEST PASS: test_handle_key_lowercase_g_jump_top");
    }

    // ==================== Function key tests ====================

    #[test]
    fn test_handle_key_f1_help() {
        init_test_logging();
        info!("TEST START: test_handle_key_f1_help");
        let f1 = KeyEvent::new(KeyCode::F(1));
        assert_eq!(handle_key(f1), Action::Help);
        info!("TEST PASS: test_handle_key_f1_help");
    }

    #[test]
    fn test_handle_key_other_function_keys_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_other_function_keys_tick");
        // F2-F12 should be Tick (no action)
        for i in 2..=12 {
            let f_key = KeyEvent::new(KeyCode::F(i));
            assert_eq!(handle_key(f_key), Action::Tick, "F{} should be Tick", i);
        }
        info!("TEST PASS: test_handle_key_other_function_keys_tick");
    }

    // ==================== Vim-style navigation tests ====================

    #[test]
    fn test_handle_key_vim_j_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_j_down");
        let j = KeyEvent::new(KeyCode::Char('j'));
        assert_eq!(handle_key(j), Action::Down);
        info!("TEST PASS: test_handle_key_vim_j_down");
    }

    #[test]
    fn test_handle_key_vim_k_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_k_up");
        let k = KeyEvent::new(KeyCode::Char('k'));
        assert_eq!(handle_key(k), Action::Up);
        info!("TEST PASS: test_handle_key_vim_k_up");
    }

    // ==================== Arrow key navigation tests ====================

    #[test]
    fn test_handle_key_arrow_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_arrow_up");
        let up = KeyEvent::new(KeyCode::Up);
        assert_eq!(handle_key(up), Action::Up);
        info!("TEST PASS: test_handle_key_arrow_up");
    }

    #[test]
    fn test_handle_key_arrow_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_arrow_down");
        let down = KeyEvent::new(KeyCode::Down);
        assert_eq!(handle_key(down), Action::Down);
        info!("TEST PASS: test_handle_key_arrow_down");
    }

    // ==================== Tab navigation tests ====================

    #[test]
    fn test_handle_key_tab_next_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_tab_next_panel");
        let tab = KeyEvent::new(KeyCode::Tab);
        assert_eq!(handle_key(tab), Action::NextPanel);
        info!("TEST PASS: test_handle_key_tab_next_panel");
    }

    #[test]
    fn test_handle_key_backtab_prev_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_backtab_prev_panel");
        let backtab = KeyEvent::new(KeyCode::BackTab);
        assert_eq!(handle_key(backtab), Action::PrevPanel);
        info!("TEST PASS: test_handle_key_backtab_prev_panel");
    }

    // ==================== Action key tests ====================

    #[test]
    fn test_handle_key_slash_filter() {
        init_test_logging();
        info!("TEST START: test_handle_key_slash_filter");
        let slash = KeyEvent::new(KeyCode::Char('/'));
        assert_eq!(handle_key(slash), Action::Filter);
        info!("TEST PASS: test_handle_key_slash_filter");
    }

    #[test]
    fn test_handle_key_y_copy() {
        init_test_logging();
        info!("TEST START: test_handle_key_y_copy");
        let y = KeyEvent::new(KeyCode::Char('y'));
        assert_eq!(handle_key(y), Action::Copy);
        info!("TEST PASS: test_handle_key_y_copy");
    }

    #[test]
    fn test_handle_key_r_refresh() {
        init_test_logging();
        info!("TEST START: test_handle_key_r_refresh");
        let r = KeyEvent::new(KeyCode::Char('r'));
        assert_eq!(handle_key(r), Action::Refresh);
        info!("TEST PASS: test_handle_key_r_refresh");
    }

    #[test]
    fn test_handle_key_enter_select() {
        init_test_logging();
        info!("TEST START: test_handle_key_enter_select");
        let enter = KeyEvent::new(KeyCode::Enter);
        assert_eq!(handle_key(enter), Action::Select);
        info!("TEST PASS: test_handle_key_enter_select");
    }

    #[test]
    fn test_handle_key_backspace_back() {
        init_test_logging();
        info!("TEST START: test_handle_key_backspace_back");
        let backspace = KeyEvent::new(KeyCode::Backspace);
        assert_eq!(handle_key(backspace), Action::Back);
        info!("TEST PASS: test_handle_key_backspace_back");
    }

    #[test]
    fn test_handle_key_question_mark_help() {
        init_test_logging();
        info!("TEST START: test_handle_key_question_mark_help");
        let qmark = KeyEvent::new(KeyCode::Char('?'));
        assert_eq!(handle_key(qmark), Action::Help);
        info!("TEST PASS: test_handle_key_question_mark_help");
    }

    // ==================== Input mode text entry tests ====================

    #[test]
    fn test_handle_key_input_mode_letters() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_letters");
        for c in 'a'..='z' {
            let key = KeyEvent::new(KeyCode::Char(c));
            assert_eq!(handle_key_input_mode(key), Action::TextInput(c));
        }
        info!("TEST PASS: test_handle_key_input_mode_letters");
    }

    #[test]
    fn test_handle_key_input_mode_numbers() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_numbers");
        for c in '0'..='9' {
            let key = KeyEvent::new(KeyCode::Char(c));
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
            let key = KeyEvent::new(KeyCode::Char(c));
            assert_eq!(handle_key_input_mode(key), Action::TextInput(c));
        }
        info!("TEST PASS: test_handle_key_input_mode_special_chars");
    }

    #[test]
    fn test_handle_key_input_mode_backspace_delete_char() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_backspace_delete_char");
        let backspace = KeyEvent::new(KeyCode::Backspace);
        assert_eq!(handle_key_input_mode(backspace), Action::DeleteChar);
        info!("TEST PASS: test_handle_key_input_mode_backspace_delete_char");
    }

    #[test]
    fn test_handle_key_input_mode_esc_back() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_esc_back");
        let esc = KeyEvent::new(KeyCode::Escape);
        assert_eq!(handle_key_input_mode(esc), Action::Back);
        info!("TEST PASS: test_handle_key_input_mode_esc_back");
    }

    #[test]
    fn test_handle_key_input_mode_enter_select() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_enter_select");
        let enter = KeyEvent::new(KeyCode::Enter);
        assert_eq!(handle_key_input_mode(enter), Action::Select);
        info!("TEST PASS: test_handle_key_input_mode_enter_select");
    }

    #[test]
    fn test_handle_key_input_mode_unknown_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_input_mode_unknown_tick");
        // Arrow keys in input mode should be Tick (no action)
        let up = KeyEvent::new(KeyCode::Up);
        assert_eq!(handle_key_input_mode(up), Action::Tick);
        let down = KeyEvent::new(KeyCode::Down);
        assert_eq!(handle_key_input_mode(down), Action::Tick);
        info!("TEST PASS: test_handle_key_input_mode_unknown_tick");
    }

    // ==================== Page navigation tests ====================

    #[test]
    fn test_handle_key_page_up() {
        init_test_logging();
        info!("TEST START: test_handle_key_page_up");
        let pgup = KeyEvent::new(KeyCode::PageUp);
        assert_eq!(handle_key(pgup), Action::PageUp);
        info!("TEST PASS: test_handle_key_page_up");
    }

    #[test]
    fn test_handle_key_page_down() {
        init_test_logging();
        info!("TEST START: test_handle_key_page_down");
        let pgdn = KeyEvent::new(KeyCode::PageDown);
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
        let z = KeyEvent::new(KeyCode::Char('z'));
        assert_eq!(handle_key(z), Action::Tick);
        // 'x' is now mapped to CancelBuild, so test a truly unmapped char
        let m = KeyEvent::new(KeyCode::Char('m'));
        assert_eq!(handle_key(m), Action::Tick);
        info!("TEST PASS: test_handle_key_unknown_char_tick");
    }

    #[test]
    fn test_handle_key_home_end_tick() {
        init_test_logging();
        info!("TEST START: test_handle_key_home_end_tick");
        // Home and End keys are not mapped
        let home = KeyEvent::new(KeyCode::Home);
        assert_eq!(handle_key(home), Action::Tick);
        let end = KeyEvent::new(KeyCode::End);
        assert_eq!(handle_key(end), Action::Tick);
        info!("TEST PASS: test_handle_key_home_end_tick");
    }

    // ==================== Drain/Enable worker tests ====================

    #[test]
    fn test_handle_key_drain_worker() {
        init_test_logging();
        info!("TEST START: test_handle_key_drain_worker");
        let d = KeyEvent::new(KeyCode::Char('d'));
        assert_eq!(handle_key(d), Action::DrainWorker);
        info!("TEST PASS: test_handle_key_drain_worker");
    }

    #[test]
    fn test_handle_key_enable_worker() {
        init_test_logging();
        info!("TEST START: test_handle_key_enable_worker");
        let e = KeyEvent::new(KeyCode::Char('e'));
        assert_eq!(handle_key(e), Action::EnableWorker);
        info!("TEST PASS: test_handle_key_enable_worker");
    }

    #[test]
    fn test_drain_enable_action_equality() {
        init_test_logging();
        info!("TEST START: test_drain_enable_action_equality");
        assert_eq!(Action::DrainWorker, Action::DrainWorker);
        assert_eq!(Action::EnableWorker, Action::EnableWorker);
        assert_ne!(Action::DrainWorker, Action::EnableWorker);
        assert_ne!(Action::DrainWorker, Action::Tick);
        info!("TEST PASS: test_drain_enable_action_equality");
    }

    // ==================== Worker/Build action key tests ====================

    #[test]
    fn test_handle_key_drain_all_workers() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('D'));
        assert_eq!(handle_key(key), Action::DrainAllWorkers);
    }

    #[test]
    fn test_handle_key_enable_all_workers() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('E'));
        assert_eq!(handle_key(key), Action::EnableAllWorkers);
    }

    #[test]
    fn test_handle_key_cancel_build() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('x'));
        assert_eq!(handle_key(key), Action::CancelBuild);
    }

    #[test]
    fn test_handle_key_force_kill_build() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('X'));
        assert_eq!(handle_key(key), Action::ForceKillBuild);
    }

    // ==================== Confirm dialog key tests ====================

    #[test]
    fn test_confirm_key_y_confirms() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('y'));
        assert_eq!(handle_confirm_key(key), Action::Confirm);
    }

    #[test]
    fn test_confirm_key_enter_confirms() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Enter);
        assert_eq!(handle_confirm_key(key), Action::Confirm);
    }

    #[test]
    fn test_confirm_key_n_dismisses() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('n'));
        assert_eq!(handle_confirm_key(key), Action::Dismiss);
    }

    #[test]
    fn test_confirm_key_esc_dismisses() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Escape);
        assert_eq!(handle_confirm_key(key), Action::Dismiss);
    }

    #[test]
    fn test_confirm_key_other_is_tick() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('z'));
        assert_eq!(handle_confirm_key(key), Action::Tick);
    }

    #[test]
    fn test_confirm_key_ctrl_c_quits() {
        init_test_logging();
        let key = KeyEvent::new(KeyCode::Char('c')).with_modifiers(Modifiers::CTRL);
        assert_eq!(handle_confirm_key(key), Action::Quit);
    }

    // ==================== Vim panel navigation tests ====================

    #[test]
    fn test_handle_key_vim_h_prev_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_h_prev_panel");
        let h = KeyEvent::new(KeyCode::Char('h'));
        assert_eq!(handle_key(h), Action::PrevPanel);
        info!("TEST PASS: test_handle_key_vim_h_prev_panel");
    }

    #[test]
    fn test_handle_key_vim_l_next_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_vim_l_next_panel");
        let l = KeyEvent::new(KeyCode::Char('l'));
        assert_eq!(handle_key(l), Action::NextPanel);
        info!("TEST PASS: test_handle_key_vim_l_next_panel");
    }

    #[test]
    fn test_handle_key_left_arrow_prev_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_left_arrow_prev_panel");
        let left = KeyEvent::new(KeyCode::Left);
        assert_eq!(handle_key(left), Action::PrevPanel);
        info!("TEST PASS: test_handle_key_left_arrow_prev_panel");
    }

    #[test]
    fn test_handle_key_right_arrow_next_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_right_arrow_next_panel");
        let right = KeyEvent::new(KeyCode::Right);
        assert_eq!(handle_key(right), Action::NextPanel);
        info!("TEST PASS: test_handle_key_right_arrow_next_panel");
    }

    #[test]
    fn test_handle_key_shift_h_jump_first_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_shift_h_jump_first_panel");
        let shift_h = KeyEvent::new(KeyCode::Char('H')).with_modifiers(Modifiers::SHIFT);
        assert_eq!(handle_key(shift_h), Action::JumpToPanel(0));
        info!("TEST PASS: test_handle_key_shift_h_jump_first_panel");
    }

    #[test]
    fn test_handle_key_shift_l_jump_last_panel() {
        init_test_logging();
        info!("TEST START: test_handle_key_shift_l_jump_last_panel");
        let shift_l = KeyEvent::new(KeyCode::Char('L')).with_modifiers(Modifiers::SHIFT);
        assert_eq!(handle_key(shift_l), Action::JumpToPanel(3));
        info!("TEST PASS: test_handle_key_shift_l_jump_last_panel");
    }

    // ==================== Number key panel jump tests ====================

    #[test]
    fn test_handle_key_number_1_jump_workers() {
        init_test_logging();
        info!("TEST START: test_handle_key_number_1_jump_workers");
        let key = KeyEvent::new(KeyCode::Char('1'));
        assert_eq!(handle_key(key), Action::JumpToPanel(0));
        info!("TEST PASS: test_handle_key_number_1_jump_workers");
    }

    #[test]
    fn test_handle_key_number_2_jump_active_builds() {
        init_test_logging();
        info!("TEST START: test_handle_key_number_2_jump_active_builds");
        let key = KeyEvent::new(KeyCode::Char('2'));
        assert_eq!(handle_key(key), Action::JumpToPanel(1));
        info!("TEST PASS: test_handle_key_number_2_jump_active_builds");
    }

    #[test]
    fn test_handle_key_number_3_jump_build_history() {
        init_test_logging();
        info!("TEST START: test_handle_key_number_3_jump_build_history");
        let key = KeyEvent::new(KeyCode::Char('3'));
        assert_eq!(handle_key(key), Action::JumpToPanel(2));
        info!("TEST PASS: test_handle_key_number_3_jump_build_history");
    }

    #[test]
    fn test_handle_key_number_4_jump_logs() {
        init_test_logging();
        info!("TEST START: test_handle_key_number_4_jump_logs");
        let key = KeyEvent::new(KeyCode::Char('4'));
        assert_eq!(handle_key(key), Action::JumpToPanel(3));
        info!("TEST PASS: test_handle_key_number_4_jump_logs");
    }

    #[test]
    fn test_jump_to_panel_action_equality() {
        init_test_logging();
        info!("TEST START: test_jump_to_panel_action_equality");
        assert_eq!(Action::JumpToPanel(0), Action::JumpToPanel(0));
        assert_ne!(Action::JumpToPanel(0), Action::JumpToPanel(1));
        assert_ne!(Action::JumpToPanel(0), Action::Tick);
        info!("TEST PASS: test_jump_to_panel_action_equality");
    }
}
