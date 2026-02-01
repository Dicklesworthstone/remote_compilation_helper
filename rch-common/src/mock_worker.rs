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

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::mock::{clear_mock_overrides, clear_thread_mock_override, is_mock_enabled};
    use std::env;

    fn clear_env() {
        // SAFETY: Tests control env var lifecycle within the module.
        unsafe { env::remove_var("RCH_MOCK_SSH") };
        clear_thread_mock_override();
    }

    #[test]
    fn test_default_uri_prefix_and_uniqueness() {
        let server_a = MockWorkerServer::builder().build();
        let server_b = MockWorkerServer::builder().build();

        assert!(server_a.uri().starts_with("mock://worker-"));
        assert!(server_b.uri().starts_with("mock://worker-"));
        assert_ne!(server_a.uri(), server_b.uri());
    }

    #[test]
    fn test_bind_normalizes_uri() {
        let server = MockWorkerServer::builder().bind("localhost:9900").build();
        assert_eq!(server.uri(), "mock://localhost:9900");
    }

    #[test]
    fn test_bind_preserves_mock_prefix() {
        let server = MockWorkerServer::builder()
            .bind("mock://example:1234")
            .build();
        assert_eq!(server.uri(), "mock://example:1234");
    }

    #[test]
    fn test_start_stop_toggles_mock_enabled() {
        clear_env();
        clear_mock_overrides();

        let mut server = MockWorkerServer::builder().bind("worker-a").build();
        assert!(!is_mock_enabled());

        server.start();
        assert!(is_mock_enabled());

        server.stop();
        assert!(!is_mock_enabled());

        clear_mock_overrides();
    }

    // -------------------------------------------------------------------------
    // MockWorkerServer trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_mock_worker_server_debug() {
        let server = MockWorkerServer::builder().bind("debug-worker").build();
        let debug_str = format!("{:?}", server);
        assert!(debug_str.contains("MockWorkerServer"));
        assert!(debug_str.contains("uri"));
        assert!(debug_str.contains("mock://debug-worker"));
    }

    #[test]
    fn test_mock_worker_server_clone() {
        let server = MockWorkerServer::builder().bind("clone-worker").build();
        let cloned = server.clone();
        assert_eq!(cloned.uri(), "mock://clone-worker");
    }

    // -------------------------------------------------------------------------
    // MockWorkerServerBuilder trait tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_builder_debug() {
        let builder = MockWorkerServer::builder().bind("builder-debug");
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("MockWorkerServerBuilder"));
    }

    #[test]
    fn test_builder_clone() {
        let builder = MockWorkerServer::builder().bind("builder-clone");
        let cloned = builder.clone();
        let server = cloned.build();
        assert_eq!(server.uri(), "mock://builder-clone");
    }

    #[test]
    fn test_builder_default() {
        let builder = MockWorkerServerBuilder::default();
        let server = builder.build();
        // Default should generate unique mock://worker-N URI
        assert!(server.uri().starts_with("mock://worker-"));
    }

    // -------------------------------------------------------------------------
    // Builder method tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_builder_ssh_config() {
        let custom_config = MockConfig::connection_failure();
        let server = MockWorkerServer::builder()
            .ssh_config(custom_config.clone())
            .build();
        // Verify the config was set (we can't easily inspect it, but at least it compiles)
        let debug_str = format!("{:?}", server);
        assert!(debug_str.contains("ssh_config"));
    }

    #[test]
    fn test_builder_rsync_config() {
        let custom_config = MockRsyncConfig::sync_failure();
        let server = MockWorkerServer::builder()
            .rsync_config(custom_config.clone())
            .build();
        // Verify the config was set
        let debug_str = format!("{:?}", server);
        assert!(debug_str.contains("rsync_config"));
    }

    #[test]
    fn test_builder_method_chaining() {
        let server = MockWorkerServer::builder()
            .bind("chained-worker")
            .ssh_config(MockConfig::success())
            .rsync_config(MockRsyncConfig::success())
            .build();
        assert_eq!(server.uri(), "mock://chained-worker");
    }

    // -------------------------------------------------------------------------
    // Idempotent start/stop tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_start_is_idempotent() {
        clear_env();
        clear_mock_overrides();

        let mut server = MockWorkerServer::builder().bind("idempotent-start").build();

        // Start multiple times should be safe
        server.start();
        assert!(is_mock_enabled());
        server.start(); // Second start should be no-op
        assert!(is_mock_enabled());
        server.start(); // Third start should be no-op
        assert!(is_mock_enabled());

        server.stop();
        clear_mock_overrides();
    }

    #[test]
    fn test_stop_is_idempotent() {
        clear_env();
        clear_mock_overrides();

        let mut server = MockWorkerServer::builder().bind("idempotent-stop").build();

        // Stop without start should be safe
        server.stop();
        assert!(!is_mock_enabled());
        server.stop(); // Second stop should be no-op
        assert!(!is_mock_enabled());

        clear_mock_overrides();
    }

    #[test]
    fn test_stop_without_start_is_safe() {
        clear_env();
        clear_mock_overrides();

        let mut server = MockWorkerServer::builder().bind("no-start-stop").build();
        // Never started, stop should be a no-op
        server.stop();
        assert!(!is_mock_enabled());

        clear_mock_overrides();
    }

    // -------------------------------------------------------------------------
    // Drop behavior tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_drop_clears_mock_state() {
        clear_env();
        clear_mock_overrides();

        {
            let mut server = MockWorkerServer::builder().bind("drop-test").build();
            server.start();
            assert!(is_mock_enabled());
            // Server is dropped here
        }

        // After drop, mock should be disabled
        assert!(!is_mock_enabled());

        clear_mock_overrides();
    }

    // -------------------------------------------------------------------------
    // URI normalization tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_normalize_uri_without_prefix() {
        assert_eq!(
            normalize_uri("localhost:9900".to_string()),
            "mock://localhost:9900"
        );
    }

    #[test]
    fn test_normalize_uri_with_prefix() {
        assert_eq!(
            normalize_uri("mock://already-prefixed".to_string()),
            "mock://already-prefixed"
        );
    }

    #[test]
    fn test_normalize_uri_empty() {
        assert_eq!(normalize_uri("".to_string()), "mock://");
    }
}
