## Overview

Implement automatic detection of installed AI coding agents and idempotent hook configuration for each supported agent. This should be safe to run repeatedly, never clobber user settings, create backups before modifications, and produce a clear status report.

This bead uses documented config locations and hook formats for each agent. Where hook APIs are not documented, the system provides detection-only with manual guidance.

## Supported Agents

| Agent | Config Location | Hook Support | Detection | Version Command |
|-------|----------------|--------------|-----------|-----------------|
| Claude Code | ~/.config/claude-code | PreToolUse (JSON) | ✓ Full | `claude --version` |
| Gemini CLI | ~/.gemini | pre_tool_use (JSON) | ✓ Full | `gemini --version` |
| Codex CLI | ~/.codex | Hooks (TOML) | ✓ Full | `codex --version` |
| Cursor | ~/.cursor | Unknown | Detection only | Settings UI |
| Continue.dev | ~/.continue | config.json | ✓ Partial | N/A |
| Windsurf | ~/.codeium/windsurf | Unknown | Detection only | N/A |
| Aider | ~/.aider | None | Detection only | `aider --version` |
| Cline | ~/.cline | Unknown | Detection only | N/A |

## Goals

1. Detect installed agents and their versions
2. Report current hook status for each agent
3. Install hooks safely (idempotent, backup, atomic)
4. Uninstall hooks cleanly (remove only RCH entries)
5. Support JSON output for scripting
6. Provide manual guidance for unsupported agents
7. Environment variable overrides for config paths

## CLI Interface

```
# Status and detection
rch agents                     # Show all detected agents with status
rch agents detect              # Explicit detection scan
rch agents --json              # JSON output for scripting

# Hook management
rch agents install             # Install hooks for all supported agents
rch agents install --agent claude    # Install for specific agent
rch agents install --all       # Install for all detected agents
rch agents uninstall           # Remove RCH hooks from all agents
rch agents uninstall --agent claude  # Remove from specific agent

# Verification
rch agents verify              # Verify hooks are working
rch agents verify --agent claude
```

## Data Model

```rust
// rch/src/agents/mod.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistry {
    pub agents: Vec<AgentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Internal identifier
    pub id: &'static str,
    /// Display name
    pub display_name: &'static str,
    /// Environment variable to override config dir
    pub config_dir_env: Option<&'static str>,
    /// Default config directory (with ~ expansion)
    pub default_config_dir: &'static str,
    /// Config file name
    pub config_file: &'static str,
    /// Command to get version (None if no CLI)
    pub version_command: Option<&'static str>,
    /// Hook support level
    pub hook_support: HookSupport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookSupport {
    /// Full hook support with known format
    Full { format: HookFormat },
    /// Partial support (may need manual steps)
    Partial { format: HookFormat, notes: &'static str },
    /// Detection only, no hook installation
    DetectionOnly { reason: &'static str },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookFormat {
    /// Claude Code PreToolUse hooks
    ClaudeCode,
    /// Gemini CLI pre_tool_use hooks
    GeminiCli,
    /// Codex CLI hooks in TOML
    CodexCli,
    /// Continue.dev config.json
    ContinueDev,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAgent {
    pub config: AgentConfig,
    pub detected: bool,
    pub version: Option<String>,
    pub config_path: Option<PathBuf>,
    pub hook_status: HookStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookStatus {
    /// Hook is installed and active
    Active,
    /// Agent detected, hook can be installed
    Ready,
    /// Hook installation not supported
    NotSupported,
    /// Hook exists but may be outdated
    NeedsUpdate,
    /// Agent not detected
    NotDetected,
}
```

## Agent Registry

```rust
impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: vec![
                AgentConfig {
                    id: "claude_code",
                    display_name: "Claude Code",
                    config_dir_env: Some("CLAUDE_CONFIG_DIR"),
                    default_config_dir: "~/.config/claude-code",
                    config_file: "settings.json",
                    version_command: Some("claude --version"),
                    hook_support: HookSupport::Full {
                        format: HookFormat::ClaudeCode,
                    },
                },
                AgentConfig {
                    id: "gemini_cli",
                    display_name: "Gemini CLI",
                    config_dir_env: Some("GEMINI_CONFIG_DIR"),
                    default_config_dir: "~/.gemini",
                    config_file: "settings.json",
                    version_command: Some("gemini --version"),
                    hook_support: HookSupport::Full {
                        format: HookFormat::GeminiCli,
                    },
                },
                AgentConfig {
                    id: "codex_cli",
                    display_name: "Codex CLI",
                    config_dir_env: Some("CODEX_CONFIG_DIR"),
                    default_config_dir: "~/.codex",
                    config_file: "config.toml",
                    version_command: Some("codex --version"),
                    hook_support: HookSupport::Full {
                        format: HookFormat::CodexCli,
                    },
                },
                AgentConfig {
                    id: "continue_dev",
                    display_name: "Continue.dev",
                    config_dir_env: None,
                    default_config_dir: "~/.continue",
                    config_file: "config.json",
                    version_command: None,
                    hook_support: HookSupport::Partial {
                        format: HookFormat::ContinueDev,
                        notes: "Requires IDE restart after hook installation",
                    },
                },
                AgentConfig {
                    id: "cursor",
                    display_name: "Cursor",
                    config_dir_env: None,
                    default_config_dir: "~/.cursor",
                    config_file: "settings.json",
                    version_command: None,
                    hook_support: HookSupport::DetectionOnly {
                        reason: "Hook API not publicly documented",
                    },
                },
                AgentConfig {
                    id: "windsurf",
                    display_name: "Windsurf",
                    config_dir_env: None,
                    default_config_dir: "~/.codeium/windsurf",
                    config_file: "settings.json",
                    version_command: None,
                    hook_support: HookSupport::DetectionOnly {
                        reason: "Hook API not publicly documented",
                    },
                },
                AgentConfig {
                    id: "aider",
                    display_name: "Aider",
                    config_dir_env: Some("AIDER_CONFIG_DIR"),
                    default_config_dir: "~/.aider",
                    config_file: ".aider.conf.yml",
                    version_command: Some("aider --version"),
                    hook_support: HookSupport::DetectionOnly {
                        reason: "Aider does not support pre-execution hooks",
                    },
                },
                AgentConfig {
                    id: "cline",
                    display_name: "Cline",
                    config_dir_env: None,
                    default_config_dir: "~/.cline",
                    config_file: "settings.json",
                    version_command: None,
                    hook_support: HookSupport::DetectionOnly {
                        reason: "Hook API not publicly documented",
                    },
                },
            ],
        }
    }
}
```

## Hook Installation

```rust
// rch/src/agents/hooks.rs

pub struct HookInstaller {
    rch_binary_path: PathBuf,
}

impl HookInstaller {
    /// Install hook for a specific agent
    pub fn install(&self, agent: &DetectedAgent) -> Result<InstallResult> {
        match &agent.config.hook_support {
            HookSupport::Full { format } | HookSupport::Partial { format, .. } => {
                self.install_hook(agent, format)
            }
            HookSupport::DetectionOnly { reason } => {
                Ok(InstallResult::NotSupported(reason.to_string()))
            }
        }
    }

    fn install_hook(&self, agent: &DetectedAgent, format: &HookFormat) -> Result<InstallResult> {
        let config_path = agent.config_path.as_ref()
            .ok_or_else(|| anyhow!("Config path not found"))?;

        // 1. Read existing config
        let content = std::fs::read_to_string(config_path)?;

        // 2. Check if hook already exists
        if self.hook_exists(&content, format)? {
            return Ok(InstallResult::AlreadyInstalled);
        }

        // 3. Create timestamped backup
        let backup_path = self.create_backup(config_path)?;

        // 4. Add hook to config
        let updated = self.add_hook(&content, format)?;

        // 5. Atomic write
        let temp_path = config_path.with_extension("tmp");
        std::fs::write(&temp_path, &updated)?;
        std::fs::rename(&temp_path, config_path)?;

        Ok(InstallResult::Installed { backup_path })
    }

    fn hook_exists(&self, content: &str, format: &HookFormat) -> Result<bool> {
        match format {
            HookFormat::ClaudeCode => {
                let config: serde_json::Value = serde_json::from_str(content)?;
                Ok(config.pointer("/hooks/PreToolUse")
                    .and_then(|h| h.as_array())
                    .map(|hooks| hooks.iter().any(|h|
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(|c| c.contains("rch"))
                            .unwrap_or(false)
                    ))
                    .unwrap_or(false))
            }
            // Similar for other formats...
            _ => Ok(false)
        }
    }
}

#[derive(Debug)]
pub enum InstallResult {
    Installed { backup_path: PathBuf },
    AlreadyInstalled,
    Updated { backup_path: PathBuf },
    NotSupported(String),
}
```

## Output Examples

### Human Output
```
AI Coding Agent Status
══════════════════════

Agent           Status       Hook        Version
────────────────────────────────────────────────────
Claude Code     ✓ Detected   ✓ Active    1.0.34
Gemini CLI      ✓ Detected   ○ Ready     2.1.0
Codex CLI       ✓ Detected   ✓ Active    0.9.2
Continue.dev    ✓ Detected   ○ Ready     -
Cursor          ✓ Detected   ⊘ Manual    -
Windsurf        ○ Not found  -           -
Aider           ✓ Detected   ⊘ N/A       0.50.1
Cline           ○ Not found  -           -

Legend: ✓ Active  ○ Ready  ⊘ Manual/N/A  - Not applicable

Tip: Run 'rch agents install' to install hooks for all ready agents.
```

### JSON Output
```json
{
  "agents": [
    {
      "id": "claude_code",
      "display_name": "Claude Code",
      "detected": true,
      "version": "1.0.34",
      "config_path": "/home/user/.config/claude-code/settings.json",
      "hook_status": "active",
      "hook_supported": true
    },
    {
      "id": "cursor",
      "detected": true,
      "version": null,
      "config_path": "/home/user/.cursor/settings.json",
      "hook_status": "not_supported",
      "hook_supported": false,
      "manual_instructions": "Hook API not publicly documented. See docs for manual setup."
    }
  ],
  "summary": {
    "total_detected": 5,
    "hooks_active": 2,
    "hooks_ready": 2,
    "manual_required": 1
  }
}
```

## Implementation Files

```
rch/src/
├── agents/
│   ├── mod.rs           # Public API, AgentRegistry
│   ├── detect.rs        # Detection logic
│   ├── hooks.rs         # Hook installation/uninstallation
│   ├── formats/
│   │   ├── mod.rs
│   │   ├── claude.rs    # Claude Code hook format
│   │   ├── gemini.rs    # Gemini CLI hook format
│   │   ├── codex.rs     # Codex CLI hook format (TOML)
│   │   └── continue.rs  # Continue.dev format
│   └── verify.rs        # Hook verification
├── commands/
│   └── agents.rs        # CLI command
```

## Testing Requirements

### Unit Tests (rch/src/agents/tests/)

**detect_test.rs**
```rust
#[test]
fn test_detect_claude_code() {
    let tmp = TempDir::new().unwrap();
    let config_dir = tmp.path().join(".config/claude-code");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("settings.json"), "{}").unwrap();

    let registry = AgentRegistry::new();
    let result = registry.detect_with_base(tmp.path());

    let claude = result.iter().find(|a| a.config.id == "claude_code").unwrap();
    assert!(claude.detected);
}

#[test]
fn test_detect_respects_env_override() {
    let tmp = TempDir::new().unwrap();
    let custom_dir = tmp.path().join("custom-claude");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("settings.json"), "{}").unwrap();

    std::env::set_var("CLAUDE_CONFIG_DIR", &custom_dir);
    let registry = AgentRegistry::new();
    let result = registry.detect();

    let claude = result.iter().find(|a| a.config.id == "claude_code").unwrap();
    assert_eq!(claude.config_path, Some(custom_dir.join("settings.json")));
}
```

**hooks_test.rs**
```rust
#[test]
fn test_hook_installation_idempotent() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("settings.json");
    std::fs::write(&config_path, r#"{"hooks": {}}"#).unwrap();

    let installer = HookInstaller::new("/usr/local/bin/rch");

    // First install
    let result1 = installer.install_claude_hook(&config_path).unwrap();
    assert!(matches!(result1, InstallResult::Installed { .. }));

    // Second install (should be idempotent)
    let result2 = installer.install_claude_hook(&config_path).unwrap();
    assert!(matches!(result2, InstallResult::AlreadyInstalled));
}

#[test]
fn test_hook_creates_backup() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("settings.json");
    std::fs::write(&config_path, r#"{"existing": "config"}"#).unwrap();

    let installer = HookInstaller::new("/usr/local/bin/rch");
    let result = installer.install_claude_hook(&config_path).unwrap();

    if let InstallResult::Installed { backup_path } = result {
        assert!(backup_path.exists());
        let backup_content = std::fs::read_to_string(backup_path).unwrap();
        assert!(backup_content.contains("existing"));
    } else {
        panic!("Expected Installed result");
    }
}

#[test]
fn test_uninstall_removes_only_rch_hooks() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("settings.json");
    std::fs::write(&config_path, r#"{
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "command": "/usr/local/bin/rch hook"},
                {"matcher": "Write", "command": "/other/tool"}
            ]
        }
    }"#).unwrap();

    let installer = HookInstaller::new("/usr/local/bin/rch");
    installer.uninstall_claude_hook(&config_path).unwrap();

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(!content.contains("rch hook"));
    assert!(content.contains("/other/tool"));
}
```

### Integration Tests (rch/tests/agents_integration.rs)

```rust
#[test]
fn test_agents_command_output() {
    let tmp = TempDir::new().unwrap();
    setup_mock_agents(&tmp);

    Command::cargo_bin("rch")
        .unwrap()
        .env("HOME", tmp.path())
        .arg("agents")
        .assert()
        .success()
        .stdout(predicate::str::contains("Claude Code"))
        .stdout(predicate::str::contains("Detected"));
}

#[test]
fn test_agents_json_output() {
    let tmp = TempDir::new().unwrap();
    setup_mock_agents(&tmp);

    let output = Command::cargo_bin("rch")
        .unwrap()
        .env("HOME", tmp.path())
        .args(["agents", "--json"])
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json.get("agents").is_some());
    assert!(json.get("summary").is_some());
}

#[test]
fn test_agents_install_all() {
    let tmp = TempDir::new().unwrap();
    setup_mock_agents(&tmp);

    Command::cargo_bin("rch")
        .unwrap()
        .env("HOME", tmp.path())
        .args(["agents", "install", "--all"])
        .assert()
        .success();

    // Verify hooks were installed
    let claude_config = tmp.path().join(".config/claude-code/settings.json");
    let content = std::fs::read_to_string(claude_config).unwrap();
    assert!(content.contains("rch hook"));
}
```

### E2E Test Script (scripts/e2e_agents_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date -Iseconds)] $*" >&2; }
pass() { log "✓ PASS: $*"; }
fail() { log "✗ FAIL: $*"; exit 1; }

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
export HOME="$TEST_DIR"

# Setup mock agent configs
setup_mock_agents() {
    mkdir -p "$HOME/.config/claude-code"
    echo '{"hooks":{}}' > "$HOME/.config/claude-code/settings.json"

    mkdir -p "$HOME/.gemini"
    echo '{}' > "$HOME/.gemini/settings.json"

    mkdir -p "$HOME/.codex"
    echo '' > "$HOME/.codex/config.toml"
}

setup_mock_agents

# Test 1: Detection finds agents
log "Test 1: Agent detection"
OUTPUT=$("$RCH" agents --json)
echo "$OUTPUT" | jq -e '.agents | length > 0' > /dev/null || fail "Should detect agents"
pass "Agent detection"

# Test 2: Install hooks
log "Test 2: Hook installation"
"$RCH" agents install --all --yes 2>&1
grep -q "rch hook" "$HOME/.config/claude-code/settings.json" || fail "Hook not installed"
pass "Hook installation"

# Test 3: Idempotent install
log "Test 3: Idempotent install"
"$RCH" agents install --all --yes 2>&1 | grep -q "Already installed" || fail "Should report already installed"
pass "Idempotent install"

# Test 4: Backup created
log "Test 4: Backup creation"
ls "$HOME/.config/claude-code/"*.bak >/dev/null 2>&1 || fail "Backup not created"
pass "Backup creation"

# Test 5: Uninstall
log "Test 5: Hook uninstall"
"$RCH" agents uninstall --all --yes 2>&1
grep -q "rch hook" "$HOME/.config/claude-code/settings.json" && fail "Hook not removed"
pass "Hook uninstall"

log "All agent E2E tests passed!"
```

## Logging Requirements

- DEBUG: Config path resolution for each agent
- DEBUG: Hook existence check results
- INFO: Agent detection summary
- INFO: Hook installation/uninstallation results
- WARN: Agent detected but hook not supported
- WARN: Config file parse errors (continue with detection)
- ERROR: Hook installation failures with remediation

## Success Criteria

- [ ] Detects all 8 listed agents when installed
- [ ] Respects environment variable overrides
- [ ] Hook installation is fully idempotent
- [ ] Creates timestamped backups before modifications
- [ ] Uninstall removes only RCH hooks
- [ ] JSON output matches schema
- [ ] Clear guidance for unsupported agents
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass

## Dependencies

- remote_compilation_helper-0dl: Uses idempotent primitives

## Blocks

- remote_compilation_helper-3d1: Setup wizard uses agent detection
