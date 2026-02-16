//! E2E Test Fixtures
//!
//! Provides pre-built configurations, sample data, and test fixtures
//! for end-to-end testing.

use serde::{Deserialize, Serialize};
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
        #[cfg(unix)]
        let user = whoami::username().unwrap_or_else(|_| "unknown".to_string());
        #[cfg(not(unix))]
        let user = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            id: id.to_string(),
            host: "localhost".to_string(),
            user,
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
        if self.workers.is_empty() {
            "workers = []\n".to_string()
        } else {
            self.workers
                .iter()
                .map(|w| w.to_toml())
                .collect::<Vec<_>>()
                .join("\n")
        }
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

/// Default namespace used for deterministic multi-repo path dependency fixtures.
pub const DEFAULT_MULTI_REPO_FIXTURE_NAMESPACE: &str = "rch_multi_repo_path_deps";

/// Canonical root expected for multi-repo fixture generation.
pub const DEFAULT_MULTI_REPO_CANONICAL_ROOT: &str = "/data/projects";

/// Alias root expected to symlink to [`DEFAULT_MULTI_REPO_CANONICAL_ROOT`].
pub const DEFAULT_MULTI_REPO_ALIAS_ROOT: &str = "/dp";

/// Error type for multi-repo fixture generation and reset.
#[derive(Debug, thiserror::Error)]
pub enum MultiRepoFixtureError {
    #[error("I/O failure while managing fixtures: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid path topology: {0}")]
    InvalidTopology(String),
    #[error("Failed to serialize fixture manifest: {0}")]
    ManifestSerialize(#[from] serde_json::Error),
}

/// Result type for multi-repo fixture operations.
pub type MultiRepoFixtureResult<T> = Result<T, MultiRepoFixtureError>;

/// Readiness expectation for a fixture scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureReadiness {
    Ready,
    ExpectedFailure,
}

/// Expected failure mode for a non-ready fixture scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureFailureMode {
    MissingPathDependency,
    InvalidCargoManifest,
    OutsideCanonicalRootDependency,
}

/// Test layers that can consume the fixture scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureLayer {
    Unit,
    Integration,
    FaultInjection,
    Soak,
}

/// Metadata describing one deterministic multi-repo fixture scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRepoFixtureMetadata {
    pub id: String,
    pub description: String,
    pub readiness: FixtureReadiness,
    pub failure_mode: Option<FixtureFailureMode>,
    pub canonical_entrypoint: PathBuf,
    pub alias_entrypoint: PathBuf,
    pub canonical_repo_paths: Vec<PathBuf>,
    pub assertion_targets: Vec<String>,
    pub reusable_layers: Vec<FixtureLayer>,
}

impl MultiRepoFixtureMetadata {
    /// Returns true when the scenario is expected to be build-ready.
    pub fn expected_ready(&self) -> bool {
        matches!(self.readiness, FixtureReadiness::Ready)
    }
}

/// Configuration for deterministic multi-repo fixture generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiRepoFixtureConfig {
    canonical_root: PathBuf,
    alias_root: PathBuf,
    namespace: String,
}

impl Default for MultiRepoFixtureConfig {
    fn default() -> Self {
        Self {
            canonical_root: PathBuf::from(DEFAULT_MULTI_REPO_CANONICAL_ROOT),
            alias_root: PathBuf::from(DEFAULT_MULTI_REPO_ALIAS_ROOT),
            namespace: DEFAULT_MULTI_REPO_FIXTURE_NAMESPACE.to_string(),
        }
    }
}

impl MultiRepoFixtureConfig {
    /// Build a config with explicit topology roots and namespace.
    pub fn new(canonical_root: PathBuf, alias_root: PathBuf, namespace: impl Into<String>) -> Self {
        Self {
            canonical_root,
            alias_root,
            namespace: namespace.into(),
        }
    }

    /// Canonical root where fixture namespace will be created.
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Alias root expected to resolve to canonical root.
    pub fn alias_root(&self) -> &Path {
        &self.alias_root
    }

    /// Namespace directory under canonical root.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// Deterministic multi-repo fixture set rooted under a namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRepoFixtureSet {
    pub canonical_root: PathBuf,
    pub alias_root: PathBuf,
    pub namespace: String,
    pub canonical_namespace_root: PathBuf,
    pub alias_namespace_root: PathBuf,
    pub manifest_path: PathBuf,
    pub fixtures: Vec<MultiRepoFixtureMetadata>,
}

impl MultiRepoFixtureSet {
    /// Returns fixture metadata by id.
    pub fn fixture(&self, id: &str) -> Option<&MultiRepoFixtureMetadata> {
        self.fixtures.iter().find(|fixture| fixture.id == id)
    }
}

/// Resets and recreates deterministic multi-repo fixtures under default `/data/projects` + `/dp`.
pub fn reset_default_multi_repo_fixtures() -> MultiRepoFixtureResult<MultiRepoFixtureSet> {
    reset_multi_repo_fixtures(&MultiRepoFixtureConfig::default())
}

/// Resets and recreates deterministic multi-repo fixtures for the provided topology.
pub fn reset_multi_repo_fixtures(
    config: &MultiRepoFixtureConfig,
) -> MultiRepoFixtureResult<MultiRepoFixtureSet> {
    validate_fixture_topology(config.canonical_root(), config.alias_root())?;

    let canonical_root = std::fs::canonicalize(config.canonical_root())?;
    let alias_root = config.alias_root().to_path_buf();
    let canonical_namespace_root = canonical_root.join(config.namespace());
    if canonical_namespace_root.exists() {
        std::fs::remove_dir_all(&canonical_namespace_root)?;
    }
    std::fs::create_dir_all(&canonical_namespace_root)?;

    let fixtures = create_multi_repo_scenarios(
        &canonical_root,
        &alias_root,
        config.namespace(),
        &canonical_namespace_root,
    )?;
    let alias_namespace_root = alias_root.join(config.namespace());
    let manifest_path = canonical_namespace_root.join("fixture_manifest.json");

    let fixture_set = MultiRepoFixtureSet {
        canonical_root,
        alias_root,
        namespace: config.namespace().to_string(),
        canonical_namespace_root,
        alias_namespace_root,
        manifest_path,
        fixtures,
    };

    let serialized = serde_json::to_string_pretty(&fixture_set)?;
    std::fs::write(&fixture_set.manifest_path, serialized)?;
    Ok(fixture_set)
}

fn validate_fixture_topology(
    canonical_root: &Path,
    alias_root: &Path,
) -> MultiRepoFixtureResult<()> {
    if !canonical_root.is_absolute() {
        return Err(MultiRepoFixtureError::InvalidTopology(format!(
            "canonical root must be absolute: {}",
            canonical_root.display()
        )));
    }
    if !alias_root.is_absolute() {
        return Err(MultiRepoFixtureError::InvalidTopology(format!(
            "alias root must be absolute: {}",
            alias_root.display()
        )));
    }

    std::fs::create_dir_all(canonical_root)?;
    let canonical_resolved = std::fs::canonicalize(canonical_root)?;

    let alias_meta = std::fs::symlink_metadata(alias_root).map_err(|error| {
        MultiRepoFixtureError::InvalidTopology(format!(
            "alias root metadata unavailable for {}: {}",
            alias_root.display(),
            error
        ))
    })?;
    if !alias_meta.file_type().is_symlink() {
        return Err(MultiRepoFixtureError::InvalidTopology(format!(
            "alias root is not a symlink: {}",
            alias_root.display()
        )));
    }

    let raw_target = std::fs::read_link(alias_root)?;
    let absolute_target = if raw_target.is_absolute() {
        raw_target
    } else {
        alias_root
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .join(raw_target)
    };
    let alias_target = std::fs::canonicalize(&absolute_target)?;
    if alias_target != canonical_resolved {
        return Err(MultiRepoFixtureError::InvalidTopology(format!(
            "alias root {} points to {}, expected {}",
            alias_root.display(),
            alias_target.display(),
            canonical_resolved.display()
        )));
    }

    Ok(())
}

fn create_multi_repo_scenarios(
    canonical_root: &Path,
    alias_root: &Path,
    namespace: &str,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<Vec<MultiRepoFixtureMetadata>> {
    Ok(vec![
        create_ready_relative_transitive_fixture(canonical_root, alias_root, namespace_root)?,
        create_ready_alias_absolute_fixture(canonical_root, alias_root, namespace, namespace_root)?,
        create_missing_dependency_fixture(canonical_root, alias_root, namespace_root)?,
        create_outside_root_dependency_fixture(canonical_root, alias_root, namespace_root)?,
        create_invalid_manifest_fixture(canonical_root, alias_root, namespace_root)?,
    ])
}

fn all_fixture_layers() -> Vec<FixtureLayer> {
    vec![
        FixtureLayer::Unit,
        FixtureLayer::Integration,
        FixtureLayer::FaultInjection,
        FixtureLayer::Soak,
    ]
}

fn create_ready_relative_transitive_fixture(
    canonical_root: &Path,
    alias_root: &Path,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<MultiRepoFixtureMetadata> {
    let scenario_root = namespace_root.join("ready_relative_transitive");
    let core_repo = scenario_root.join("core_lib");
    let util_repo = scenario_root.join("util_lib");
    let app_repo = scenario_root.join("app_main");

    write_library_repo(
        &core_repo,
        "fixture_core_lib",
        &[],
        r#"pub fn core_value() -> &'static str {
    "fixture-core"
}
"#,
    )?;

    write_library_repo(
        &util_repo,
        "fixture_util_lib",
        &[("fixture_core_lib", "../core_lib")],
        r#"pub fn util_value() -> String {
    format!("{}-util", fixture_core_lib::core_value())
}
"#,
    )?;

    write_binary_repo(
        &app_repo,
        "fixture_app_main",
        &[("fixture_util_lib", "../util_lib")],
        r#"fn main() {
    println!("{}", fixture_util_lib::util_value());
}
"#,
    )?;

    Ok(MultiRepoFixtureMetadata {
        id: "ready_relative_transitive".to_string(),
        description: "Three-repo transitive graph using relative Cargo path dependencies."
            .to_string(),
        readiness: FixtureReadiness::Ready,
        failure_mode: None,
        canonical_entrypoint: app_repo.clone(),
        alias_entrypoint: to_alias_path(&app_repo, canonical_root, alias_root),
        canonical_repo_paths: vec![core_repo, util_repo, app_repo],
        assertion_targets: vec![
            "cargo metadata succeeds from app_main".to_string(),
            "transitive dependency resolution includes fixture_core_lib".to_string(),
            "entrypoint Cargo.toml uses relative path ../util_lib".to_string(),
        ],
        reusable_layers: all_fixture_layers(),
    })
}

fn create_ready_alias_absolute_fixture(
    canonical_root: &Path,
    alias_root: &Path,
    namespace: &str,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<MultiRepoFixtureMetadata> {
    let scenario_root = namespace_root.join("ready_alias_absolute");
    let shared_repo = scenario_root.join("alias_shared");
    let app_repo = scenario_root.join("alias_app");

    write_library_repo(
        &shared_repo,
        "fixture_alias_shared",
        &[],
        r#"pub fn alias_value() -> &'static str {
    "fixture-alias"
}
"#,
    )?;

    let alias_dep_path = alias_root
        .join(namespace)
        .join("ready_alias_absolute")
        .join("alias_shared");
    write_binary_repo(
        &app_repo,
        "fixture_alias_app",
        &[(
            "fixture_alias_shared",
            alias_dep_path.to_string_lossy().as_ref(),
        )],
        r#"fn main() {
    println!("{}", fixture_alias_shared::alias_value());
}
"#,
    )?;

    Ok(MultiRepoFixtureMetadata {
        id: "ready_alias_absolute".to_string(),
        description: "Two-repo graph using absolute /dp alias path dependency.".to_string(),
        readiness: FixtureReadiness::Ready,
        failure_mode: None,
        canonical_entrypoint: app_repo.clone(),
        alias_entrypoint: to_alias_path(&app_repo, canonical_root, alias_root),
        canonical_repo_paths: vec![shared_repo, app_repo],
        assertion_targets: vec![
            "cargo metadata succeeds from alias_app".to_string(),
            format!(
                "entrypoint dependency path starts with {}",
                alias_root.display()
            ),
            "alias root form and canonical form resolve to same repo graph".to_string(),
        ],
        reusable_layers: all_fixture_layers(),
    })
}

fn create_missing_dependency_fixture(
    canonical_root: &Path,
    alias_root: &Path,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<MultiRepoFixtureMetadata> {
    let scenario_root = namespace_root.join("fail_missing_path_dep");
    let app_repo = scenario_root.join("missing_app");
    write_binary_repo(
        &app_repo,
        "fixture_missing_dep_app",
        &[("fixture_missing_dep_lib", "../missing_lib")],
        r#"fn main() {
    println!("this should fail dependency resolution");
}
"#,
    )?;

    Ok(MultiRepoFixtureMetadata {
        id: "fail_missing_path_dep".to_string(),
        description: "Fixture with missing local path dependency for readiness gating.".to_string(),
        readiness: FixtureReadiness::ExpectedFailure,
        failure_mode: Some(FixtureFailureMode::MissingPathDependency),
        canonical_entrypoint: app_repo.clone(),
        alias_entrypoint: to_alias_path(&app_repo, canonical_root, alias_root),
        canonical_repo_paths: vec![app_repo],
        assertion_targets: vec![
            "cargo metadata fails with missing path dependency".to_string(),
            "error output references ../missing_lib".to_string(),
        ],
        reusable_layers: all_fixture_layers(),
    })
}

fn create_outside_root_dependency_fixture(
    canonical_root: &Path,
    alias_root: &Path,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<MultiRepoFixtureMetadata> {
    let scenario_root = namespace_root.join("fail_outside_canonical_dep");
    let app_repo = scenario_root.join("outside_app");
    let outside_dep = "/tmp/rch_outside_canonical_dep_lib";

    write_binary_repo(
        &app_repo,
        "fixture_outside_dep_app",
        &[("fixture_outside_dep_lib", outside_dep)],
        r#"fn main() {
    println!("outside root dependency fixture");
}
"#,
    )?;

    Ok(MultiRepoFixtureMetadata {
        id: "fail_outside_canonical_dep".to_string(),
        description: "Fixture referencing absolute dependency path outside canonical root."
            .to_string(),
        readiness: FixtureReadiness::ExpectedFailure,
        failure_mode: Some(FixtureFailureMode::OutsideCanonicalRootDependency),
        canonical_entrypoint: app_repo.clone(),
        alias_entrypoint: to_alias_path(&app_repo, canonical_root, alias_root),
        canonical_repo_paths: vec![app_repo],
        assertion_targets: vec![
            format!("manifest dependency path references {}", outside_dep),
            "preflight topology checks reject outside-canonical dependency".to_string(),
        ],
        reusable_layers: all_fixture_layers(),
    })
}

fn create_invalid_manifest_fixture(
    canonical_root: &Path,
    alias_root: &Path,
    namespace_root: &Path,
) -> MultiRepoFixtureResult<MultiRepoFixtureMetadata> {
    let scenario_root = namespace_root.join("fail_invalid_manifest");
    let app_repo = scenario_root.join("invalid_app");
    std::fs::create_dir_all(app_repo.join("src"))?;
    std::fs::write(
        app_repo.join("Cargo.toml"),
        r#"[package]
name = "fixture_invalid_manifest"
version = "0.1.0"
edition = "2024"

[dependencies
serde = "1"
"#,
    )?;
    std::fs::write(
        app_repo.join("src/main.rs"),
        "fn main() { println!(\"invalid manifest fixture\"); }\n",
    )?;

    Ok(MultiRepoFixtureMetadata {
        id: "fail_invalid_manifest".to_string(),
        description: "Fixture with malformed Cargo.toml syntax to trigger parse failure."
            .to_string(),
        readiness: FixtureReadiness::ExpectedFailure,
        failure_mode: Some(FixtureFailureMode::InvalidCargoManifest),
        canonical_entrypoint: app_repo.clone(),
        alias_entrypoint: to_alias_path(&app_repo, canonical_root, alias_root),
        canonical_repo_paths: vec![app_repo],
        assertion_targets: vec![
            "cargo metadata fails with TOML parse error".to_string(),
            "error output references Cargo.toml parse context".to_string(),
        ],
        reusable_layers: all_fixture_layers(),
    })
}

fn write_library_repo(
    repo_dir: &Path,
    package_name: &str,
    path_dependencies: &[(&str, &str)],
    lib_src: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(repo_dir.join("src"))?;
    std::fs::write(
        repo_dir.join("Cargo.toml"),
        cargo_toml(package_name, path_dependencies),
    )?;
    std::fs::write(repo_dir.join("src/lib.rs"), lib_src)?;
    Ok(())
}

fn write_binary_repo(
    repo_dir: &Path,
    package_name: &str,
    path_dependencies: &[(&str, &str)],
    main_src: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(repo_dir.join("src"))?;
    std::fs::write(
        repo_dir.join("Cargo.toml"),
        cargo_toml(package_name, path_dependencies),
    )?;
    std::fs::write(repo_dir.join("src/main.rs"), main_src)?;
    Ok(())
}

fn cargo_toml(package_name: &str, path_dependencies: &[(&str, &str)]) -> String {
    let mut dependencies_block = String::new();
    for (name, path) in path_dependencies {
        dependencies_block.push_str(&format!("{name} = {{ path = \"{path}\" }}\n"));
    }

    format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[dependencies]
{dependencies_block}"#
    )
}

fn to_alias_path(canonical_path: &Path, canonical_root: &Path, alias_root: &Path) -> PathBuf {
    let relative = canonical_path
        .strip_prefix(canonical_root)
        .expect("canonical path must remain under canonical root");
    alias_root.join(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    static MULTI_REPO_FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct MultiRepoPathFixture {
        root: PathBuf,
        canonical_root: PathBuf,
        alias_root: PathBuf,
    }

    #[cfg(unix)]
    impl MultiRepoPathFixture {
        fn new(prefix: &str) -> Self {
            let id = MULTI_REPO_FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "rch-e2e-multi-repo-fixtures-{}-{}-{}",
                prefix,
                std::process::id(),
                id
            ));
            let canonical_root = root.join("data/projects");
            let alias_root = root.join("dp");
            fs::create_dir_all(&canonical_root).expect("create canonical root");
            symlink(&canonical_root, &alias_root).expect("create alias symlink");
            Self {
                root,
                canonical_root,
                alias_root,
            }
        }

        fn config(&self, namespace: &str) -> MultiRepoFixtureConfig {
            MultiRepoFixtureConfig::new(
                self.canonical_root.clone(),
                self.alias_root.clone(),
                namespace.to_string(),
            )
        }
    }

    #[cfg(unix)]
    impl Drop for MultiRepoPathFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

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

    #[cfg(unix)]
    #[test]
    fn multi_repo_fixture_reset_is_deterministic() {
        let fixture = MultiRepoPathFixture::new("deterministic");
        let config = fixture.config("fixture_pack");

        let first = reset_multi_repo_fixtures(&config).expect("first reset");
        let first_manifest =
            fs::read_to_string(&first.manifest_path).expect("read first manifest json");
        assert!(first.manifest_path.exists());
        assert_eq!(first.fixtures.len(), 5);

        let drift_file = first.canonical_namespace_root.join("drift_marker.txt");
        fs::write(&drift_file, "drift").expect("write drift marker");
        assert!(drift_file.exists());

        let second = reset_multi_repo_fixtures(&config).expect("second reset");
        let second_manifest =
            fs::read_to_string(&second.manifest_path).expect("read second manifest json");

        assert!(!drift_file.exists(), "reset should remove stale files");
        assert_eq!(
            first
                .fixtures
                .iter()
                .map(|fixture| fixture.id.clone())
                .collect::<Vec<_>>(),
            second
                .fixtures
                .iter()
                .map(|fixture| fixture.id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            first_manifest, second_manifest,
            "manifest output must stay deterministic across resets"
        );
    }

    #[cfg(unix)]
    #[test]
    fn multi_repo_fixture_metadata_includes_readiness_failure_and_layers() {
        let fixture = MultiRepoPathFixture::new("metadata");
        let config = fixture.config("fixture_pack");
        let generated = reset_multi_repo_fixtures(&config).expect("generate fixture set");

        assert_eq!(generated.fixtures.len(), 5);
        for metadata in &generated.fixtures {
            assert!(!metadata.assertion_targets.is_empty());
            assert!(!metadata.reusable_layers.is_empty());
            assert!(
                metadata
                    .canonical_entrypoint
                    .starts_with(&generated.canonical_namespace_root)
            );
            assert!(
                metadata
                    .alias_entrypoint
                    .starts_with(&generated.alias_namespace_root)
            );
            if metadata.expected_ready() {
                assert!(metadata.failure_mode.is_none());
            } else {
                assert!(metadata.failure_mode.is_some());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn multi_repo_fixture_alias_absolute_scenario_uses_alias_prefix() {
        let fixture = MultiRepoPathFixture::new("alias");
        let config = fixture.config("fixture_pack");
        let generated = reset_multi_repo_fixtures(&config).expect("generate fixture set");
        let alias_fixture = generated
            .fixture("ready_alias_absolute")
            .expect("ready alias fixture metadata");

        let cargo_toml = fs::read_to_string(alias_fixture.canonical_entrypoint.join("Cargo.toml"))
            .expect("read alias app cargo toml");
        assert!(
            cargo_toml.contains(config.alias_root().to_string_lossy().as_ref()),
            "alias fixture manifest must encode alias root path"
        );
        assert!(
            cargo_toml.contains("ready_alias_absolute/alias_shared"),
            "alias fixture manifest should reference shared dependency"
        );
    }

    #[cfg(unix)]
    #[test]
    fn multi_repo_fixture_rejects_non_symlink_alias_root() {
        let id = MULTI_REPO_FIXTURE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "rch-e2e-invalid-alias-fixtures-{}-{}",
            std::process::id(),
            id
        ));
        let canonical_root = root.join("data/projects");
        let alias_root = root.join("dp");
        fs::create_dir_all(&canonical_root).expect("create canonical root");
        fs::create_dir_all(&alias_root).expect("create alias directory");

        let config = MultiRepoFixtureConfig::new(canonical_root, alias_root, "fixture_pack");
        let err = reset_multi_repo_fixtures(&config).expect_err("alias root must fail");
        assert!(matches!(err, MultiRepoFixtureError::InvalidTopology(_)));

        let _ = fs::remove_dir_all(&root);
    }
}
