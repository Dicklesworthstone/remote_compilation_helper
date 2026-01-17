//! Agent detection and hook management.
//!
//! This module provides automatic detection of installed AI coding agents
//! and idempotent hook configuration for each supported agent.
//!
//! # Supported Agents
//!
//! | Agent | Hook Support | Detection |
//! |-------|--------------|-----------|
//! | Claude Code | PreToolUse (JSON) | Full |
//! | Gemini CLI | pre_tool_use (JSON) | Full |
//! | Codex CLI | Hooks (TOML) | Full |
//! | Cursor | Unknown | Detection only |
//! | Continue.dev | config.json | Partial |
//! | Windsurf | Unknown | Detection only |
//! | Aider | None | Detection only |
//! | Cline | Unknown | Detection only |
//!
//! # Example
//!
//! ```no_run
//! use rch::agent::{detect_agents, AgentKind};
//!
//! let agents = detect_agents()?;
//! for agent in agents {
//!     println!("{}: {}", agent.kind.name(), agent.version.as_deref().unwrap_or("unknown"));
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

mod detect;
mod hook;
mod types;

pub use detect::{detect_agents, detect_single_agent};
pub use hook::{HookStatus, check_hook_status, install_hook, uninstall_hook};
pub use types::{AgentKind, DetectedAgent, HookSupport};
