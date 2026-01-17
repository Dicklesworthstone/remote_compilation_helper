//! Mock worker server helper for tests.
//!
//! This helper configures the global mock SSH/rsync overrides and provides
//! a mock:// URI for worker configs. It does not open network sockets; it is
//! intended for CI and E2E tests where real SSH is unavailable.

use crate::mock::{
    MockConfig, MockRsyncConfig, clear_mock_overrides, set_mock_enabled_override,
    set_mock_rsync_config_override, set_mock_ssh_config_override,
};
use std::sync::atomic::{AtomicUsize, Ordering};

static MOCK_WORKER_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub struct MockWorkerServer {
    uri: String,
    ssh_config: MockConfig,
    rsync_config: MockRsyncConfig,
    started: bool,
}

impl MockWorkerServer {
    pub fn builder() -> MockWorkerServerBuilder {
        MockWorkerServerBuilder::default()
    }

    /// Return the mock:// URI to use in worker configs.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Enable mock transport globally with this server's config.
    pub fn start(&mut self) {
        if self.started {
            return;
        }
        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(self.ssh_config.clone()));
        set_mock_rsync_config_override(Some(self.rsync_config.clone()));
        self.started = true;
    }

    /// Disable mock transport overrides.
    pub fn stop(&mut self) {
        if !self.started {
            return;
        }
        clear_mock_overrides();
        self.started = false;
    }
}

impl Drop for MockWorkerServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, Clone)]
pub struct MockWorkerServerBuilder {
    uri: Option<String>,
    ssh_config: MockConfig,
    rsync_config: MockRsyncConfig,
}

impl Default for MockWorkerServerBuilder {
    fn default() -> Self {
        Self {
            uri: None,
            ssh_config: MockConfig::success(),
            rsync_config: MockRsyncConfig::success(),
        }
    }
}

impl MockWorkerServerBuilder {
    /// Set the mock:// bind URI (e.g., mock://localhost:9900).
    pub fn bind(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(normalize_uri(uri.into()));
        self
    }

    /// Override mock SSH behavior.
    pub fn ssh_config(mut self, config: MockConfig) -> Self {
        self.ssh_config = config;
        self
    }

    /// Override mock rsync behavior.
    pub fn rsync_config(mut self, config: MockRsyncConfig) -> Self {
        self.rsync_config = config;
        self
    }

    pub fn build(self) -> MockWorkerServer {
        MockWorkerServer {
            uri: self.uri.unwrap_or_else(default_uri),
            ssh_config: self.ssh_config,
            rsync_config: self.rsync_config,
            started: false,
        }
    }
}

fn default_uri() -> String {
    let id = MOCK_WORKER_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    format!("mock://worker-{}", id)
}

fn normalize_uri(uri: String) -> String {
    if uri.starts_with("mock://") {
        uri
    } else {
        format!("mock://{}", uri)
    }
}
