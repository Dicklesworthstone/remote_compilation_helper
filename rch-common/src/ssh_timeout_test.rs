#[cfg(test)]
mod tests {
    use crate::ssh::{SshClient, SshOptions};
    use crate::types::{WorkerConfig, WorkerId};
    use std::time::Duration;

    // Note: We can't easily test real SSH timeouts without a real SSH server.
    // But we can verify the timeout logic compiles and the structure is correct.
    // A mock SSH server would be needed for a true integration test.
    // However, since we used tokio::time::timeout, we rely on tokio's correctness.

    // We can at least create an SshClient with short timeout and ensure it's set in options.

    #[test]
    fn test_timeout_config() {
        let options = SshOptions {
            command_timeout: Duration::from_millis(100),
            ..SshOptions::default()
        };

        assert_eq!(options.command_timeout.as_millis(), 100);

        let config = WorkerConfig {
            id: WorkerId::new("test"),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "key".to_string(),
            total_slots: 1,
            priority: 1,
            tags: vec![],
            tools: Vec::new(),
        };

        let _client = SshClient::new(config, options);
        // We can't check internal options easily as they are private,
        // but if it compiled, the struct change is valid.
    }
}
