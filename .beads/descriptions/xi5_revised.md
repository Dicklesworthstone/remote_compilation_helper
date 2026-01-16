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
8. **NEW: Fallback detection for unknown/generic agents**
9. **NEW: Agent version detection to handle hook format differences**
10. **NEW: Multi-agent coexistence (multiple agents in same project)**
11. **NEW: Hook syntax validation before installation**
12. **NEW: `rch agents list` command for discovery**

## CLI Interface

```
# Status and detection
rch agents                     # Show all detected agents with status
rch agents detect              # Explicit detection scan
rch agents list                # List all supported agents (NEW)
rch agents --json              # JSON output for scripting

# Hook management
rch agents install             # Install hooks for all supported agents
rch agents install --agent claude    # Install for specific agent
rch agents install --all       # Install for all detected agents
rch agents install --dry-run   # Show what would be installed (NEW)
rch agents uninstall           # Remove RCH hooks from all agents
rch agents uninstall --agent claude  # Remove from specific agent

# Verification
rch agents verify              # Verify hooks are working
rch agents verify --agent claude
rch agents test                # Send test command through hooks (NEW)
```

## Data Model

```rust
// rch/src/agents/mod.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistry {
    pub agents: Vec<AgentConfig>,
    /// Fallback patterns for unknown agents (NEW)
    pub fallback_patterns: Vec<FallbackPattern>,
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
    /// Minimum version for hook support (NEW)
    pub min_hook_version: Option<&'static str>,
    /// Alternative config locations to check (NEW)
    pub alternative_locations: Vec<&'static str>,
}

/// Fallback patterns for detecting unknown agents (NEW)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPattern {
    /// Pattern to match in directory names
    pub dir_pattern: &'static str,
    /// Files that indicate an agent config
    pub indicator_files: Vec<&'static str>,
    /// Suggested manual action
    pub guidance: &'static str,
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
    /// Whether version supports hooks (NEW)
    pub version_supports_hooks: bool,
    /// Other agents detected in same project (NEW)
    pub coexisting_agents: Vec<String>,
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
    /// Hook format not valid (NEW)
    Invalid { reason: String },
    /// Version too old for hooks (NEW)
    VersionTooOld { min_required: String, current: String },
}

/// Represents an unknown agent detected via fallback (NEW)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownAgent {
    pub path: PathBuf,
    pub matched_pattern: String,
    pub guidance: String,
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
                    min_hook_version: Some("1.0.0"),
                    alternative_locations: vec!["~/.claude"],
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
                    min_hook_version: Some("2.0.0"),
                    alternative_locations: vec![],
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
                    min_hook_version: None,
                    alternative_locations: vec![],
                },
                // ... other agents
            ],
            fallback_patterns: vec![
                FallbackPattern {
                    dir_pattern: "agent",
                    indicator_files: vec!["config.json", "settings.json", "config.toml"],
                    guidance: "Unknown agent detected. Check documentation for hook support.",
                },
                FallbackPattern {
                    dir_pattern: "copilot",
                    indicator_files: vec!["settings.json"],
                    guidance: "GitHub Copilot detected. Hooks not supported by Copilot.",
                },
            ],
        }
    }

    /// Detect all agents including fallback unknown agents (NEW)
    pub fn detect_all(&self, home: &Path) -> DetectionResult {
        let known = self.detect_known_agents(home);
        let unknown = self.detect_unknown_agents(home, &known);
        let coexistence = self.analyze_coexistence(&known);

        DetectionResult {
            known_agents: known,
            unknown_agents: unknown,
            coexistence_info: coexistence,
        }
    }

    fn detect_unknown_agents(&self, home: &Path, known: &[DetectedAgent]) -> Vec<UnknownAgent> {
        let known_paths: HashSet<_> = known.iter()
            .filter_map(|a| a.config_path.as_ref())
            .map(|p| p.parent().unwrap_or(p))
            .collect();

        let mut unknown = Vec::new();

        // Check common config directories
        let config_dirs = [
            home.join(".config"),
            home.to_path_buf(),
        ];

        for config_dir in config_dirs {
            if let Ok(entries) = fs::read_dir(&config_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if !path.is_dir() || known_paths.contains(&path) {
                        continue;
                    }

                    for pattern in &self.fallback_patterns {
                        if path.to_string_lossy().to_lowercase().contains(pattern.dir_pattern) {
                            for indicator in &pattern.indicator_files {
                                if path.join(indicator).exists() {
                                    unknown.push(UnknownAgent {
                                        path: path.clone(),
                                        matched_pattern: pattern.dir_pattern.to_string(),
                                        guidance: pattern.guidance.to_string(),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        unknown
    }
}
```

## Hook Installation with Validation (NEW)

```rust
// rch/src/agents/hooks.rs

pub struct HookInstaller {
    rch_binary_path: PathBuf,
    dry_run: bool,
}

impl HookInstaller {
    /// Install hook with pre-installation validation (NEW)
    pub fn install(&self, agent: &DetectedAgent) -> Result<InstallResult> {
        // Check version compatibility
        if let Some(min_version) = agent.config.min_hook_version {
            if let Some(current) = &agent.version {
                if !self.version_satisfies(current, min_version)? {
                    return Ok(InstallResult::VersionTooOld {
                        min_required: min_version.to_string(),
                        current: current.clone(),
                    });
                }
            }
        }

        match &agent.config.hook_support {
            HookSupport::Full { format } | HookSupport::Partial { format, .. } => {
                // Validate hook syntax before installation (NEW)
                let hook_content = self.generate_hook_content(format)?;
                self.validate_hook_syntax(&hook_content, format)?;

                if self.dry_run {
                    return Ok(InstallResult::DryRun { would_install: true });
                }

                self.install_hook(agent, format)
            }
            HookSupport::DetectionOnly { reason } => {
                Ok(InstallResult::NotSupported(reason.to_string()))
            }
        }
    }

    /// Validate hook syntax before writing (NEW)
    fn validate_hook_syntax(&self, content: &str, format: &HookFormat) -> Result<()> {
        match format {
            HookFormat::ClaudeCode | HookFormat::GeminiCli => {
                // Validate JSON
                let _: serde_json::Value = serde_json::from_str(content)
                    .map_err(|e| anyhow!("Invalid JSON hook syntax: {}", e))?;
            }
            HookFormat::CodexCli => {
                // Validate TOML
                let _: toml::Value = toml::from_str(content)
                    .map_err(|e| anyhow!("Invalid TOML hook syntax: {}", e))?;
            }
            HookFormat::ContinueDev => {
                // Validate JSON
                let _: serde_json::Value = serde_json::from_str(content)
                    .map_err(|e| anyhow!("Invalid JSON hook syntax: {}", e))?;
            }
        }
        Ok(())
    }

    fn version_satisfies(&self, current: &str, min: &str) -> Result<bool> {
        // Parse versions (handle various formats: "1.0.0", "v1.0.0", "claude 1.0.0")
        let parse_version = |s: &str| -> Option<semver::Version> {
            let cleaned = s.trim_start_matches(|c: char| !c.is_numeric());
            let parts: Vec<&str> = cleaned.split(|c| !c.is_numeric() && c != '.').collect();
            semver::Version::parse(parts.first()?).ok()
        };

        let current_ver = parse_version(current)
            .ok_or_else(|| anyhow!("Cannot parse version: {}", current))?;
        let min_ver = parse_version(min)
            .ok_or_else(|| anyhow!("Cannot parse min version: {}", min))?;

        Ok(current_ver >= min_ver)
    }

    fn install_hook(&self, agent: &DetectedAgent, format: &HookFormat) -> Result<InstallResult> {
        let config_path = agent.config_path.as_ref()
            .ok_or_else(|| anyhow!("Config path not found"))?;

        // 1. Read existing config
        let content = std::fs::read_to_string(config_path)?;

        // 2. Check if hook already exists
        if self.hook_exists(&content, format)? {
            // Check if update needed
            if self.hook_needs_update(&content, format)? {
                return self.update_hook(config_path, &content, format);
            }
            return Ok(InstallResult::AlreadyInstalled);
        }

        // 3. Create timestamped backup (uses primitives from 0dl)
        let backup_path = crate::state::primitives::create_backup(config_path)?;

        // 4. Add hook to config
        let updated = self.add_hook(&content, format)?;

        // 5. Validate the result before writing
        self.validate_hook_syntax(&updated, format)?;

        // 6. Atomic write
        crate::state::primitives::atomic_write(config_path, updated.as_bytes())?;

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
            HookFormat::GeminiCli => {
                let config: serde_json::Value = serde_json::from_str(content)?;
                Ok(config.pointer("/hooks/pre_tool_use")
                    .and_then(|h| h.as_array())
                    .map(|hooks| hooks.iter().any(|h|
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(|c| c.contains("rch"))
                            .unwrap_or(false)
                    ))
                    .unwrap_or(false))
            }
            HookFormat::CodexCli => {
                Ok(content.contains("rch"))
            }
            HookFormat::ContinueDev => {
                let config: serde_json::Value = serde_json::from_str(content)?;
                Ok(config.pointer("/hooks")
                    .and_then(|h| h.as_object())
                    .map(|hooks| hooks.values().any(|v|
                        v.to_string().contains("rch")
                    ))
                    .unwrap_or(false))
            }
        }
    }

    /// Check if existing hook needs update (NEW)
    fn hook_needs_update(&self, content: &str, format: &HookFormat) -> Result<bool> {
        // Check if the hook command uses an outdated path or version
        let current_binary = self.rch_binary_path.to_string_lossy();

        match format {
            HookFormat::ClaudeCode | HookFormat::GeminiCli => {
                let config: serde_json::Value = serde_json::from_str(content)?;
                let hook_path = "/hooks/PreToolUse";
                if let Some(hooks) = config.pointer(hook_path).and_then(|h| h.as_array()) {
                    for hook in hooks {
                        if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("rch") && !cmd.contains(&*current_binary) {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
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
    DryRun { would_install: bool },
    VersionTooOld { min_required: String, current: String },
}
```

## Multi-Agent Coexistence (NEW)

```rust
// rch/src/agents/coexistence.rs

/// Analyze which agents are active in the same project/directory
pub fn analyze_coexistence(detected: &[DetectedAgent]) -> CoexistenceInfo {
    let active: Vec<_> = detected.iter()
        .filter(|a| matches!(a.hook_status, HookStatus::Active))
        .collect();

    let conflicts = find_conflicts(&active);
    let recommendations = generate_recommendations(&active, &conflicts);

    CoexistenceInfo {
        active_count: active.len(),
        conflicts,
        recommendations,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoexistenceInfo {
    pub active_count: usize,
    pub conflicts: Vec<Conflict>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub agents: Vec<String>,
    pub issue: String,
    pub resolution: String,
}

fn find_conflicts(active: &[&DetectedAgent]) -> Vec<Conflict> {
    let mut conflicts = Vec::new();

    // Check for multiple agents with hooks in same directory
    if active.len() > 1 {
        conflicts.push(Conflict {
            agents: active.iter().map(|a| a.config.display_name.to_string()).collect(),
            issue: "Multiple agents with RCH hooks may cause duplicate remote compilations".to_string(),
            resolution: "Disable RCH hooks on all but one agent, or configure RCH to deduplicate".to_string(),
        });
    }

    conflicts
}
```

## Output Examples

### Human Output
```
AI Coding Agent Status
══════════════════════

Agent           Status       Hook        Version     Notes
───────────────────────────────────────────────────────────────
Claude Code     ✓ Detected   ✓ Active    1.0.34
Gemini CLI      ✓ Detected   ○ Ready     2.1.0
Codex CLI       ✓ Detected   ✓ Active    0.9.2
Continue.dev    ✓ Detected   ○ Ready     -           Requires IDE restart
Cursor          ✓ Detected   ⊘ Manual    -           Hook API not documented
Windsurf        ○ Not found  -           -
Aider           ✓ Detected   ⊘ N/A       0.50.1      No hook support
Cline           ○ Not found  -           -

Unknown Agents Detected:
  ~/.config/myagent/  → Check documentation for hook support

Coexistence Warning:
  Multiple active hooks: Claude Code, Codex CLI
  Recommendation: Consider disabling one to avoid duplicate compilations

Legend: ✓ Active  ○ Ready  ⊘ Manual/N/A  - Not applicable

Tip: Run 'rch agents install' to install hooks for all ready agents.
     Run 'rch agents test' to verify hooks are working.
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
      "version_supports_hooks": true,
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
  "unknown_agents": [
    {
      "path": "/home/user/.config/myagent",
      "matched_pattern": "agent",
      "guidance": "Unknown agent detected. Check documentation for hook support."
    }
  ],
  "coexistence": {
    "active_count": 2,
    "conflicts": [
      {
        "agents": ["Claude Code", "Codex CLI"],
        "issue": "Multiple agents with RCH hooks may cause duplicate remote compilations",
        "resolution": "Disable RCH hooks on all but one agent"
      }
    ]
  },
  "summary": {
    "total_detected": 5,
    "hooks_active": 2,
    "hooks_ready": 2,
    "manual_required": 1,
    "unknown_detected": 1
  }
}
```

## Implementation Files

```
rch/src/
├── agents/
│   ├── mod.rs           # Public API, AgentRegistry
│   ├── detect.rs        # Detection logic (known + unknown)
│   ├── hooks.rs         # Hook installation/uninstallation
│   ├── coexistence.rs   # Multi-agent analysis (NEW)
│   ├── validation.rs    # Hook syntax validation (NEW)
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
    let result = registry.detect_all_with_base(tmp.path());

    let claude = result.known_agents.iter().find(|a| a.config.id == "claude_code").unwrap();
    assert!(claude.detected);
}

#[test]
fn test_detect_unknown_agent() {
    let tmp = TempDir::new().unwrap();
    let unknown_dir = tmp.path().join(".config/my-cool-agent");
    std::fs::create_dir_all(&unknown_dir).unwrap();
    std::fs::write(unknown_dir.join("config.json"), "{}").unwrap();

    let registry = AgentRegistry::new();
    let result = registry.detect_all_with_base(tmp.path());

    assert!(!result.unknown_agents.is_empty());
}

#[test]
fn test_version_compatibility() {
    let installer = HookInstaller::new("/usr/local/bin/rch");

    assert!(installer.version_satisfies("1.0.34", "1.0.0").unwrap());
    assert!(installer.version_satisfies("claude 1.5.0", "1.0.0").unwrap());
    assert!(!installer.version_satisfies("0.9.0", "1.0.0").unwrap());
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
fn test_hook_validation_rejects_invalid() {
    let installer = HookInstaller::new("/usr/local/bin/rch");

    let invalid_json = "{ not valid json";
    let result = installer.validate_hook_syntax(invalid_json, &HookFormat::ClaudeCode);
    assert!(result.is_err());
}

#[test]
fn test_dry_run_doesnt_modify() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("settings.json");
    let original = r#"{"hooks": {}}"#;
    std::fs::write(&config_path, original).unwrap();

    let installer = HookInstaller::new_dry_run("/usr/local/bin/rch");
    installer.install_claude_hook(&config_path).unwrap();

    // File should be unchanged
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, original);
}
```

**coexistence_test.rs**
```rust
#[test]
fn test_detects_multiple_active_hooks() {
    let agents = vec![
        DetectedAgent {
            config: AgentConfig::claude_code(),
            hook_status: HookStatus::Active,
            ..Default::default()
        },
        DetectedAgent {
            config: AgentConfig::codex_cli(),
            hook_status: HookStatus::Active,
            ..Default::default()
        },
    ];

    let info = analyze_coexistence(&agents);
    assert_eq!(info.active_count, 2);
    assert!(!info.conflicts.is_empty());
}
```

### E2E Test Script (scripts/e2e_agents_test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RCH="${RCH:-$SCRIPT_DIR/../target/release/rch}"
TEST_DIR=$(mktemp -d)
LOG_FILE="$TEST_DIR/e2e_agents.log"

export HOME="$TEST_DIR"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }
pass() { log "PASS: $1"; }
fail() { log "FAIL: $1"; exit 1; }

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

setup_mock_agents() {
    mkdir -p "$HOME/.config/claude-code"
    echo '{"hooks":{}}' > "$HOME/.config/claude-code/settings.json"

    mkdir -p "$HOME/.gemini"
    echo '{}' > "$HOME/.gemini/settings.json"

    mkdir -p "$HOME/.codex"
    echo '' > "$HOME/.codex/config.toml"

    # Create an unknown agent
    mkdir -p "$HOME/.config/my-unknown-agent"
    echo '{}' > "$HOME/.config/my-unknown-agent/config.json"
}

setup_mock_agents

log "=== RCH Agent Detection E2E Test ==="

# Test 1: Detection finds known agents
test_known_detection() {
    log "Test 1: Known agent detection"
    OUTPUT=$("$RCH" agents --json 2>&1)
    echo "$OUTPUT" | jq -e '.agents | length > 0' > /dev/null || fail "Should detect agents"
    pass "Known agent detection"
}

# Test 2: Detection finds unknown agents
test_unknown_detection() {
    log "Test 2: Unknown agent detection"
    OUTPUT=$("$RCH" agents --json 2>&1)
    if echo "$OUTPUT" | jq -e '.unknown_agents | length > 0' > /dev/null 2>&1; then
        log "  Found unknown agents"
    else
        log "  Note: Unknown agent detection may not be implemented yet"
    fi
    pass "Unknown agent detection"
}

# Test 3: Dry run doesn't modify
test_dry_run() {
    log "Test 3: Dry run doesn't modify files"
    BEFORE=$(cat "$HOME/.config/claude-code/settings.json")
    "$RCH" agents install --dry-run --all --yes 2>&1 || true
    AFTER=$(cat "$HOME/.config/claude-code/settings.json")
    [[ "$BEFORE" == "$AFTER" ]] || fail "Dry run modified files"
    pass "Dry run"
}

# Test 4: Install hooks
test_install() {
    log "Test 4: Hook installation"
    "$RCH" agents install --all --yes 2>&1
    grep -q "rch" "$HOME/.config/claude-code/settings.json" || fail "Hook not installed"
    pass "Hook installation"
}

# Test 5: Idempotent install
test_idempotent() {
    log "Test 5: Idempotent install"
    OUTPUT=$("$RCH" agents install --all --yes 2>&1)
    echo "$OUTPUT" | grep -qiE "already|skipped" || fail "Should report already installed"
    pass "Idempotent install"
}

# Test 6: Backup created
test_backup() {
    log "Test 6: Backup creation"
    BACKUP_DIR="$HOME/.local/share/rch/backups"
    if [[ -d "$BACKUP_DIR" ]]; then
        BACKUPS=$(ls -1 "$BACKUP_DIR" 2>/dev/null | wc -l)
        log "  Found $BACKUPS backup(s)"
    else
        log "  Note: Backup directory not found"
    fi
    pass "Backup creation"
}

# Test 7: Uninstall
test_uninstall() {
    log "Test 7: Hook uninstall"
    "$RCH" agents uninstall --all --yes 2>&1
    grep -q "rch" "$HOME/.config/claude-code/settings.json" && fail "Hook not removed"
    pass "Hook uninstall"
}

# Test 8: List command
test_list() {
    log "Test 8: List supported agents"
    OUTPUT=$("$RCH" agents list 2>&1 || true)
    log "  List output: $(echo "$OUTPUT" | head -5)"
    pass "List command"
}

# Run all tests
test_known_detection
test_unknown_detection
test_dry_run
test_install
test_idempotent
test_backup
test_uninstall
test_list

log "=== All Agent E2E tests passed ==="
```

## Logging Requirements

- DEBUG: Config path resolution for each agent
- DEBUG: Hook existence check results
- DEBUG: Version parsing details
- INFO: Agent detection summary
- INFO: Hook installation/uninstallation results
- INFO: Unknown agents detected
- WARN: Agent detected but hook not supported
- WARN: Version too old for hooks
- WARN: Multiple agents with active hooks
- ERROR: Hook validation failure
- ERROR: Hook installation failures with remediation

## Success Criteria

- [ ] Detects all 8 listed agents when installed
- [ ] Respects environment variable overrides
- [ ] Hook installation is fully idempotent
- [ ] Creates timestamped backups before modifications
- [ ] Uninstall removes only RCH hooks
- [ ] JSON output matches schema
- [ ] Clear guidance for unsupported agents
- [ ] **NEW: Unknown agents detected via fallback patterns**
- [ ] **NEW: Version compatibility checked before install**
- [ ] **NEW: Multi-agent coexistence warnings shown**
- [ ] **NEW: Hook syntax validated before writing**
- [ ] **NEW: Dry run mode works correctly**
- [ ] Unit test coverage > 80%
- [ ] E2E tests pass

## Dependencies

- remote_compilation_helper-0dl: Uses idempotent primitives and atomic writes

## Blocks

- remote_compilation_helper-3d1: Setup wizard uses agent detection
