# Integration Hooks

This guide explains how to integrate RCH with other systems using hooks and events.

## Overview

RCH provides several integration points:
- **Pre-build hooks**: Run before compilation starts
- **Post-build hooks**: Run after compilation completes
- **Event webhooks**: HTTP callbacks for build events
- **Custom reporters**: Extend metrics and logging

## Hook Types

### Pre-Build Hooks

Execute custom logic before a build starts:

```toml
# ~/.config/rch/config.toml
[[hooks.pre_build]]
name = "cache-warmup"
command = "warm-cache.sh"
timeout_secs = 10
required = false  # Continue if hook fails
```

Hook script receives environment variables:
```bash
#!/bin/bash
# warm-cache.sh

echo "Warming cache for project: $RCH_PROJECT"
echo "Worker: $RCH_WORKER"
echo "Command: $RCH_COMMAND"

# Custom logic here
rsync -a ~/.cache/sccache/ $RCH_WORKER:/tmp/sccache/
```

### Post-Build Hooks

Execute after build completes:

```toml
[[hooks.post_build]]
name = "notify-slack"
command = "notify.sh"
on_success = true
on_failure = true
```

Additional environment variables:
```bash
#!/bin/bash
# notify.sh

if [ "$RCH_BUILD_SUCCESS" = "true" ]; then
    curl -X POST "$SLACK_WEBHOOK" -d "{\"text\": \"Build succeeded: $RCH_PROJECT\"}"
else
    curl -X POST "$SLACK_WEBHOOK" -d "{\"text\": \"Build failed: $RCH_PROJECT - $RCH_BUILD_ERROR\"}"
fi
```

### Worker Selection Hook

Override or influence worker selection:

```toml
[[hooks.select_worker]]
name = "custom-selector"
command = "select-worker.sh"
```

Script outputs worker ID:
```bash
#!/bin/bash
# select-worker.sh

# Custom selection logic
# Input: $RCH_PROJECT, $RCH_ESTIMATED_CORES, $RCH_AVAILABLE_WORKERS (JSON)

# Example: Prefer workers with project name prefix
PREFERRED=$(echo "$RCH_AVAILABLE_WORKERS" | jq -r ".[] | select(.id | startswith(\"$RCH_PROJECT\")) | .id" | head -1)

if [ -n "$PREFERRED" ]; then
    echo "$PREFERRED"
else
    # Fall back to default selection
    exit 1
fi
```

## Event Webhooks

### Configuration

```toml
# ~/.config/rch/config.toml
[webhooks]
endpoint = "https://hooks.example.com/rch"
secret = "your-webhook-secret"
events = ["build.started", "build.completed", "build.failed", "worker.status_change"]
timeout_secs = 5
retry_count = 3
```

### Event Payloads

**build.started**:
```json
{
  "event": "build.started",
  "timestamp": "2026-01-17T10:30:00Z",
  "build_id": "abc123",
  "project": "my-project",
  "command": "cargo build --release",
  "worker": "worker1",
  "workstation": "dev-machine"
}
```

**build.completed**:
```json
{
  "event": "build.completed",
  "timestamp": "2026-01-17T10:35:00Z",
  "build_id": "abc123",
  "project": "my-project",
  "worker": "worker1",
  "duration_ms": 300000,
  "success": true,
  "artifacts_size_bytes": 15000000
}
```

**build.failed**:
```json
{
  "event": "build.failed",
  "timestamp": "2026-01-17T10:32:00Z",
  "build_id": "abc123",
  "project": "my-project",
  "worker": "worker1",
  "error": "compilation error",
  "exit_code": 101,
  "fallback": "local"
}
```

**worker.status_change**:
```json
{
  "event": "worker.status_change",
  "timestamp": "2026-01-17T10:31:00Z",
  "worker": "worker1",
  "previous_status": "healthy",
  "new_status": "degraded",
  "reason": "high_latency"
}
```

### Webhook Signature

Webhooks include HMAC signature for verification:

```
X-RCH-Signature: sha256=abc123...
X-RCH-Timestamp: 1737196200
```

Verify in your handler:
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret, timestamp):
    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{payload}".encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Custom Reporters

### Implementing a Reporter

```rust
// In rch/src/reporters/mod.rs

pub trait BuildReporter: Send + Sync {
    fn report_started(&self, build: &BuildInfo);
    fn report_completed(&self, build: &BuildInfo, result: &BuildResult);
    fn report_failed(&self, build: &BuildInfo, error: &str);
}

// DataDog reporter
pub struct DataDogReporter {
    api_key: String,
    endpoint: String,
}

impl BuildReporter for DataDogReporter {
    fn report_started(&self, build: &BuildInfo) {
        // Send event to DataDog
    }

    fn report_completed(&self, build: &BuildInfo, result: &BuildResult) {
        let metrics = vec![
            Metric::gauge("rch.build.duration_ms", result.duration_ms),
            Metric::count("rch.build.total", 1, &[("status", "success")]),
        ];
        self.send_metrics(metrics);
    }

    fn report_failed(&self, build: &BuildInfo, error: &str) {
        let metrics = vec![
            Metric::count("rch.build.total", 1, &[("status", "failed")]),
        ];
        self.send_metrics(metrics);
    }
}
```

### Registering Reporters

```rust
// In daemon initialization
let reporters: Vec<Box<dyn BuildReporter>> = vec![
    Box::new(LogReporter::new()),
    Box::new(DataDogReporter::from_config(&config)?),
    Box::new(WebhookReporter::from_config(&config)?),
];

let daemon = Daemon::new(config)
    .with_reporters(reporters);
```

### Configuration

```toml
[[reporters]]
type = "datadog"
api_key = "${DATADOG_API_KEY}"
endpoint = "https://api.datadoghq.com/api/v1/series"

[[reporters]]
type = "statsd"
host = "127.0.0.1"
port = 8125
prefix = "rch"

[[reporters]]
type = "file"
path = "/var/log/rch/builds.jsonl"
format = "jsonl"
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/build.yml
name: Build with RCH

on: [push]

jobs:
  build:
    runs-on: self-hosted  # Runner with RCH configured
    steps:
      - uses: actions/checkout@v4

      - name: Ensure RCH daemon
        run: rch daemon status || rch daemon start

      - name: Build
        run: cargo build --release
        # RCH automatically intercepts

      - name: Check build location
        run: |
          if [ -n "$RCH_LAST_BUILD_WORKER" ]; then
            echo "Built on worker: $RCH_LAST_BUILD_WORKER"
          fi
```

### GitLab CI

```yaml
# .gitlab-ci.yml
build:
  stage: build
  script:
    - rch daemon status || rch daemon start
    - cargo build --release
  tags:
    - rch-runner
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent { label 'rch-enabled' }
    stages {
        stage('Build') {
            steps {
                sh 'rch daemon status || rch daemon start'
                sh 'cargo build --release'
            }
        }
    }
    post {
        always {
            sh 'rch status --json > rch-status.json'
            archiveArtifacts artifacts: 'rch-status.json'
        }
    }
}
```

## IDE Integration

### VS Code Extension

Create a VS Code extension that shows RCH status:

```typescript
// extension.ts
import * as vscode from 'vscode';
import { exec } from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    const statusBar = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left
    );

    function updateStatus() {
        exec('rch status --json', (err, stdout) => {
            if (err) {
                statusBar.text = '$(error) RCH: Down';
                statusBar.backgroundColor = new vscode.ThemeColor(
                    'statusBarItem.errorBackground'
                );
            } else {
                const status = JSON.parse(stdout);
                statusBar.text = `$(server) RCH: ${status.workers.healthy}/${status.workers.total}`;
            }
            statusBar.show();
        });
    }

    setInterval(updateStatus, 5000);
    updateStatus();

    context.subscriptions.push(statusBar);
}
```

### JetBrains Plugin

Similar integration for IntelliJ/CLion via plugin API.

## Slack/Teams Integration

### Slack App

```python
# rch_slack_bot.py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/rch-webhook', methods=['POST'])
def handle_webhook():
    event = request.json

    if event['event'] == 'build.failed':
        requests.post(SLACK_WEBHOOK, json={
            'text': f":x: Build failed on {event['worker']}",
            'attachments': [{
                'color': 'danger',
                'fields': [
                    {'title': 'Project', 'value': event['project']},
                    {'title': 'Error', 'value': event['error']},
                ]
            }]
        })

    return 'OK'
```

### Teams Connector

```python
# rch_teams_bot.py
def send_teams_notification(event):
    card = {
        "@type": "MessageCard",
        "summary": f"RCH Build {event['event']}",
        "sections": [{
            "facts": [
                {"name": "Project", "value": event['project']},
                {"name": "Worker", "value": event['worker']},
                {"name": "Status", "value": event['event']},
            ]
        }]
    }
    requests.post(TEAMS_WEBHOOK, json=card)
```

## Monitoring Integration

### Prometheus Alertmanager

```yaml
# alertmanager.yml
receivers:
  - name: rch-alerts
    webhook_configs:
      - url: 'http://rch-daemon:9090/alerts'

route:
  receiver: rch-alerts
  routes:
    - match:
        alertname: RCHWorkerDown
      receiver: rch-alerts
```

### PagerDuty Integration

```toml
# ~/.config/rch/config.toml
[integrations.pagerduty]
routing_key = "${PAGERDUTY_KEY}"
severity_mapping = { worker_down = "critical", build_failed = "warning" }
```

## Testing Integrations

### Mock Webhook Server

```bash
# Start a mock server to test webhooks
python -m http.server 8080 &

# Configure RCH to send to mock
rch config set webhooks.endpoint http://localhost:8080/webhook

# Trigger a build and check mock server logs
```

### Integration Test Suite

```bash
# Run integration tests
cargo test -p rch integration_hooks

# Test specific hook
RCH_TEST_HOOK=pre_build cargo test hook_execution
```
