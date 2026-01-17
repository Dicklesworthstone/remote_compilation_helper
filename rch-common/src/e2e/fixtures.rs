//! E2E Test Fixtures
//!
//! Provides pre-built configurations, sample data, and test fixtures
//! for end-to-end testing.

use std::path::{Path, PathBuf};

/// Sample worker configuration for tests
#[derive(Debug, Clone)]
pub struct WorkerFixture {
    pub id: String,
    pub host: String,
    pub user: String,
    pub identity_file: String,
    pub total_slots: u32,
    pub priority: u32,
}

impl WorkerFixture {
    /// Create a mock local worker (uses localhost)
    pub fn mock_local(id: &str) -> Self {
        Self {
            id: id.to_string(),
            host: "localhost".to_string(),
            user: whoami::username(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
        }
    }

    /// Generate TOML configuration for this worker
    pub fn to_toml(&self) -> String {
        format!(
            r#"[[workers]]
id = "{}"
host = "{}"
user = "{}"
identity_file = "{}"
total_slots = {}
priority = {}
"#,
            self.id, self.host, self.user, self.identity_file, self.total_slots, self.priority
        )
    }
}

/// Collection of worker fixtures
pub struct WorkersFixture {
    pub workers: Vec<WorkerFixture>,
}

impl WorkersFixture {
    /// Create an empty fixture
    pub fn empty() -> Self {
        Self { workers: vec![] }
    }

    /// Create a fixture with mock local workers
    pub fn mock_local(count: usize) -> Self {
        let workers = (0..count)
            .map(|i| WorkerFixture::mock_local(&format!("worker{}", i + 1)))
            .collect();
        Self { workers }
    }

    /// Add a worker to the fixture
    pub fn add_worker(mut self, worker: WorkerFixture) -> Self {
        self.workers.push(worker);
        self
    }

    /// Generate TOML configuration for all workers
    pub fn to_toml(&self) -> String {
        self.workers
            .iter()
            .map(|w| w.to_toml())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Sample daemon configuration for tests
#[derive(Debug, Clone)]
pub struct DaemonConfigFixture {
    pub socket_path: PathBuf,
    pub log_level: String,
    pub confidence_threshold: f64,
    pub min_local_time_ms: u64,
}

impl DaemonConfigFixture {
    /// Create a minimal daemon configuration
    pub fn minimal(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
            log_level: "debug".to_string(),
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
        }
    }

    /// Generate TOML configuration
    pub fn to_toml(&self) -> String {
        format!(
            r#"[general]
enabled = true
log_level = "{}"
socket_path = "{}"

[compilation]
confidence_threshold = {}
min_local_time_ms = {}

[transfer]
compression_level = 3
exclude_patterns = ["target/", ".git/objects/", "node_modules/"]
"#,
            self.log_level,
            self.socket_path.display(),
            self.confidence_threshold,
            self.min_local_time_ms
        )
    }
}

/// Sample Rust project for testing
#[derive(Debug, Clone)]
pub struct RustProjectFixture {
    pub name: String,
    pub version: String,
}

impl RustProjectFixture {
    /// Create a minimal Rust project fixture
    pub fn minimal(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "0.1.0".to_string(),
        }
    }

    /// Generate Cargo.toml content
    pub fn cargo_toml(&self) -> String {
        format!(
            r#"[package]
name = "{}"
version = "{}"
edition = "2024"

[dependencies]
"#,
            self.name, self.version
        )
    }

    /// Generate main.rs content
    pub fn main_rs(&self) -> String {
        r#"fn main() {
    println!("Hello from test project!");
}
"#
        .to_string()
    }

    /// Generate lib.rs content for a library project
    pub fn lib_rs(&self) -> String {
        r#"pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
"#
        .to_string()
    }

    /// Create the project files in the given directory
    pub fn create_in(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("Cargo.toml"), self.cargo_toml())?;
        std::fs::write(dir.join("src/main.rs"), self.main_rs())?;
        Ok(())
    }

    /// Create a library project in the given directory
    pub fn create_lib_in(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("Cargo.toml"), self.cargo_toml())?;
        std::fs::write(dir.join("src/lib.rs"), self.lib_rs())?;
        Ok(())
    }
}

/// Sample hook input for testing
#[derive(Debug, Clone)]
pub struct HookInputFixture {
    pub tool_name: String,
    pub command: String,
    pub description: Option<String>,
    pub session_id: Option<String>,
}

impl HookInputFixture {
    /// Create a cargo build hook input
    pub fn cargo_build() -> Self {
        Self {
            tool_name: "Bash".to_string(),
            command: "cargo build".to_string(),
            description: Some("Build the project".to_string()),
            session_id: Some("test-session-001".to_string()),
        }
    }

    /// Create a cargo test hook input
    pub fn cargo_test() -> Self {
        Self {
            tool_name: "Bash".to_string(),
            command: "cargo test".to_string(),
            description: Some("Run tests".to_string()),
            session_id: Some("test-session-001".to_string()),
        }
    }

    /// Create a non-compilation hook input
    pub fn echo(message: &str) -> Self {
        Self {
            tool_name: "Bash".to_string(),
            command: format!("echo {message}"),
            description: Some("Echo message".to_string()),
            session_id: Some("test-session-001".to_string()),
        }
    }

    /// Create a custom hook input
    pub fn custom(command: &str) -> Self {
        Self {
            tool_name: "Bash".to_string(),
            command: command.to_string(),
            description: None,
            session_id: Some("test-session-001".to_string()),
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        let desc = match &self.description {
            Some(d) => format!(r#""description": "{d}","#),
            None => String::new(),
        };
        let session = match &self.session_id {
            Some(s) => format!(r#", "session_id": "{s}""#),
            None => String::new(),
        };

        format!(
            r#"{{"tool_name": "{}", "tool_input": {{{}"command": "{}"}}{}}}
"#,
            self.tool_name, desc, self.command, session
        )
    }
}

/// Test case metadata
#[derive(Debug, Clone)]
pub struct TestCaseFixture {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
}

impl TestCaseFixture {
    /// Create a new test case fixture
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            tags: vec![],
        }
    }

    /// Add a tag to the test case
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_fixture_toml() {
        let worker = WorkerFixture::mock_local("test-worker");
        let toml = worker.to_toml();
        assert!(toml.contains("id = \"test-worker\""));
        assert!(toml.contains("host = \"localhost\""));
    }

    #[test]
    fn test_workers_fixture_toml() {
        let fixture = WorkersFixture::mock_local(2);
        let toml = fixture.to_toml();
        assert!(toml.contains("id = \"worker1\""));
        assert!(toml.contains("id = \"worker2\""));
    }

    #[test]
    fn test_daemon_config_toml() {
        let config = DaemonConfigFixture::minimal(Path::new("/tmp/rch.sock"));
        let toml = config.to_toml();
        assert!(toml.contains("socket_path = \"/tmp/rch.sock\""));
        assert!(toml.contains("confidence_threshold = 0.85"));
    }

    #[test]
    fn test_rust_project_fixture() {
        let project = RustProjectFixture::minimal("test-project");
        let cargo_toml = project.cargo_toml();
        assert!(cargo_toml.contains("name = \"test-project\""));
        assert!(cargo_toml.contains("edition = \"2024\""));
    }

    #[test]
    fn test_hook_input_fixture() {
        let input = HookInputFixture::cargo_build();
        let json = input.to_json();
        assert!(json.contains("\"tool_name\": \"Bash\""));
        assert!(json.contains("\"command\": \"cargo build\""));
    }

    #[test]
    fn test_hook_input_custom() {
        let input = HookInputFixture::custom("cargo test --release");
        let json = input.to_json();
        assert!(json.contains("\"command\": \"cargo test --release\""));
    }
}
