# Monitoring Guide

This guide covers monitoring RCH in production environments.

## Built-in Monitoring

### Status Commands

```bash
# Overall system status
rch status

# Worker health and slots
rch status --workers

# Active and recent builds
rch status --jobs

# Aggregate statistics
rch status --stats

# Circuit breaker states
rch status --circuits
```

### JSON Output

For programmatic monitoring:

```bash
# Machine-readable output
rch status --json
rch status --workers --json
rch status --jobs --json
```

Example JSON output:
```json
{
  "daemon": {
    "running": true,
    "uptime_secs": 3600,
    "version": "0.2.0"
  },
  "workers": {
    "total": 4,
    "healthy": 3,
    "degraded": 1,
    "unreachable": 0
  },
  "builds": {
    "active": 5,
    "completed_last_hour": 42,
    "failed_last_hour": 2
  }
}
```

### Daemon Logs

```bash
# Tail daemon logs
rch daemon logs

# With filters
rch daemon logs --tail 100
rch daemon logs --level warn
rch daemon logs --since "1 hour ago"
```

## Health Check Script

Create a health check for your monitoring system:

```bash
#!/bin/bash
# rch-health-check.sh

set -e

# Check daemon
if ! rch daemon status >/dev/null 2>&1; then
    echo "CRITICAL: RCH daemon not running"
    exit 2
fi

# Check workers
WORKER_STATUS=$(rch status --workers --json)
UNHEALTHY=$(echo "$WORKER_STATUS" | jq '.workers | map(select(.status != "healthy")) | length')

if [ "$UNHEALTHY" -gt 0 ]; then
    echo "WARNING: $UNHEALTHY unhealthy workers"
    exit 1
fi

echo "OK: RCH healthy"
exit 0
```

## Metrics Collection

### Prometheus Integration

RCH can expose metrics for Prometheus (if enabled):

```toml
# ~/.config/rch/config.toml
[metrics]
enabled = true
endpoint = "0.0.0.0:9090"
path = "/metrics"
```

Available metrics:
- `rch_builds_total{worker, status}` - Total builds by worker and status
- `rch_build_duration_seconds` - Build duration histogram
- `rch_worker_slots_available{worker}` - Available slots per worker
- `rch_worker_status{worker, status}` - Worker health status
- `rch_transfer_bytes_total{direction}` - Bytes transferred
- `rch_circuit_state{worker, state}` - Circuit breaker states

### OpenTelemetry (OTLP) Export

The doctor/hook event metrics (`rch_doctor_*`, `rch_hook_*`,
`rch_request_duration_seconds`) are mirrored to an OpenTelemetry collector
over OTLP/gRPC when enabled. The Prometheus inventory remains the single
source of truth — OTLP carries the *same* metric names and labels, so both
exposition surfaces can run simultaneously.

Enable it with environment variables (no config-file change needed):

```bash
export RCH_OTEL_ENABLED=1
# Preferred RCH-specific endpoint var; falls back to the OTel standard
# OTEL_EXPORTER_OTLP_ENDPOINT if unset.
export RCH_OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_SERVICE_NAME="rch"               # resource service.name (default: rch)
export RCH_OTEL_EXPORT_INTERVAL_SECS=30      # periodic push cadence (default: 30)
```

Behavior:
- Export activates only when **both** `RCH_OTEL_ENABLED` is truthy **and** an
  endpoint is set. Otherwise the pipeline stays off (Prometheus-only).
- Fail-open: if the exporter cannot be built (bad endpoint, missing runtime),
  RCH logs `otlp.exporter.build_failed` and continues with Prometheus only.
- Histogram bucket boundaries match the Prometheus definitions
  (hook hot-path buckets stay sub-millisecond).

### StatsD/DataDog

```toml
# ~/.config/rch/config.toml
[metrics]
statsd_endpoint = "127.0.0.1:8125"
statsd_prefix = "rch"
```

### Custom Metrics Script

Collect metrics periodically:

```bash
#!/bin/bash
# rch-metrics.sh - Run every minute via cron

STATUS=$(rch status --json)

# Extract metrics
ACTIVE_BUILDS=$(echo "$STATUS" | jq '.builds.active')
HEALTHY_WORKERS=$(echo "$STATUS" | jq '.workers.healthy')
TOTAL_SLOTS=$(echo "$STATUS" | jq '.workers.total_slots')
USED_SLOTS=$(echo "$STATUS" | jq '.workers.used_slots')

# Send to your metrics system
curl -X POST "http://metrics.example.com/api/v1/push" \
    -d "rch.builds.active=$ACTIVE_BUILDS" \
    -d "rch.workers.healthy=$HEALTHY_WORKERS" \
    -d "rch.slots.total=$TOTAL_SLOTS" \
    -d "rch.slots.used=$USED_SLOTS"
```

## Alerting

### Alert Conditions

| Condition | Severity | Recommended Action |
|-----------|----------|-------------------|
| Daemon not running | Critical | Auto-restart via systemd |
| All workers unreachable | Critical | Page on-call |
| Worker circuit open | Warning | Investigate, may self-recover |
| Worker degraded | Info | Monitor, check if persists |
| High build queue | Warning | Add workers or reduce load |
| Transfer failures | Warning | Check network |

### Webhook Alerts

```toml
# ~/.config/rch/config.toml
[alerts]
webhook_url = "https://hooks.slack.com/services/..."
alert_on = ["daemon_down", "circuit_open", "all_workers_down"]
```

### Reliability Verdict Webhooks

`rch doctor --reliability --watch` continuously re-runs the reliability
probe suite and computes a tri-state verdict (`Healthy` / `Degraded` /
`Failing`). Configure first-class webhooks to fire the moment the verdict
*transitions*, so an on-call engineer is paged within ~50ms instead of
waiting on a log-shipper pipeline.

```toml
# ~/.config/rch/config.toml
[doctor.webhooks]
# Bound on concurrent in-flight deliveries (shared across endpoints).
# When exhausted, a delivery is dropped and journaled rather than queued
# unboundedly.
max_inflight = 16

[[doctor.webhooks.endpoints]]
name = "ops-slack"
url = "https://hooks.slack.com/services/T0/B0/..."
format = "slack"                 # slack | pagerduty | generic_json
on_transitions = ["healthy_to_degraded", "any_to_failing", "failing_to_healthy"]
retry_max = 3
retry_backoff_ms = 200           # doubles each retry (200, 400, 800, …)
timeout_ms = 5000
enabled = true
# Optional HMAC-SHA256 signing. The named env var holds the secret; the
# signature is sent as `X-RCH-Signature: sha256=<hex>`.
signing_secret_env = "RCH_WEBHOOK_HMAC"

[[doctor.webhooks.endpoints]]
name = "pagerduty-critical"
url = "https://events.pagerduty.com/v2/enqueue"
format = "pagerduty"
on_transitions = ["any_to_failing"]   # `resolve` auto-fires on any_to_healthy
# Secrets are NEVER stored in config — only the NAME of the env var that
# holds them is. The runtime reads it at dispatch time.
routing_key_env = "RCH_PAGERDUTY_ROUTING_KEY"
enabled = true
```

**Transition predicates** (`on_transitions`): `healthy_to_degraded`,
`degraded_to_failing`, `any_to_failing`, `any_to_degraded`,
`failing_to_healthy`, `degraded_to_healthy`, `any_to_healthy`,
`any_to_any`. An empty list never fires; `enabled = false` is a
per-endpoint kill switch. The implicit baseline for the first sweep is
`Healthy`, so a watch session that starts in a bad state still pages.

Every delivery attempt (and its outcome) is journaled to the
`rch::doctor::webhook` tracing target for post-mortem audit. Webhook
dispatch is fail-open: a misconfigured or unreachable endpoint never
affects the watch loop's verdict or exit code.

### Email Alerts

```bash
#!/bin/bash
# rch-alert.sh

if ! rch daemon status >/dev/null 2>&1; then
    echo "RCH daemon is down on $(hostname)" | \
        mail -s "CRITICAL: RCH Daemon Down" oncall@example.com
fi
```

### PagerDuty Integration

```bash
#!/bin/bash
# Alert to PagerDuty on critical issues

PD_KEY="your-pagerduty-integration-key"

if ! rch daemon status >/dev/null 2>&1; then
    curl -X POST "https://events.pagerduty.com/v2/enqueue" \
        -H "Content-Type: application/json" \
        -d "{
            \"routing_key\": \"$PD_KEY\",
            \"event_action\": \"trigger\",
            \"payload\": {
                \"summary\": \"RCH daemon down on $(hostname)\",
                \"severity\": \"critical\",
                \"source\": \"$(hostname)\"
            }
        }"
fi
```

## Dashboards

### Grafana Dashboard

Import the provided Grafana dashboard from `docs/observability/grafana-dashboard.json`:

```bash
# Import via Grafana UI:
# 1. Go to Dashboards > Import
# 2. Upload the JSON file or paste its contents
# 3. Select your Prometheus data source
```

Key panels included:
1. **Overview** - Healthy workers, active builds, queue depth, slot utilization
2. **Build Metrics** - Throughput by result, duration percentiles
3. **Worker Metrics** - Slots per worker, health check latency, status
4. **Decision Latency (SLA Critical)** - P95/P99 for non-compilation (<1ms) and compilation (<5ms)
5. **Circuit Breaker** - State per worker, trip/recovery events
6. **Transfer Metrics** - Upload/download throughput and duration
7. **Classification Tiers** - Distribution and latency by tier
8. **API Metrics** - Request rate by endpoint, active connections

### Prometheus AlertManager Rules

Deploy the alert rules from `docs/observability/prometheus-alerts.yaml`:

```bash
# Add to your Prometheus alerting rules configuration:
cp docs/observability/prometheus-alerts.yaml /etc/prometheus/rules/rch-alerts.yaml

# Or include via prometheus.yml:
# rule_files:
#   - "rules/rch-alerts.yaml"
```

Alert groups:
- **rch-worker-health** - Worker offline, stale, degraded alerts
- **rch-circuit-breaker** - Circuit breaker open, high trip rate
- **rch-build-health** - Failure rate, queue depth alerts
- **rch-decision-latency-sla** - CRITICAL alerts for latency SLA breaches
- **rch-transfer** - Slow transfer warnings
- **rch-daemon** - Daemon down, high connection count
- **rch-slot-utilization** - Capacity planning alerts

### Terminal Dashboard

Use the built-in TUI (if available):

```bash
rch dashboard
```

Or a simple watch:

```bash
watch -n 5 'rch status --workers'
```

## Log Analysis

### Key Log Patterns

```bash
# Find errors
rch daemon logs | grep -i error

# Find slow transfers
rch daemon logs | grep "transfer.*ms" | awk '$NF > 5000'

# Find circuit breaker events
rch daemon logs | grep -i "circuit"

# Find selection events
rch daemon logs | grep -i "selected.*worker"
```

### Log Shipping

Forward logs to your log aggregation system:

```bash
# For systemd journals
journalctl --user -u rchd -f | nc logstash.example.com 5000

# Or configure rsyslog/fluentd/filebeat
```

### Log Levels

Control log verbosity:

```toml
# ~/.config/rch/config.toml
[general]
log_level = "info"  # error, warn, info, debug, trace
```

Or at runtime:
```bash
RUST_LOG=debug rchd
```

## Periodic Health Reports

Generate daily reports:

```bash
#!/bin/bash
# rch-daily-report.sh

echo "RCH Daily Report - $(date)"
echo "=========================="
echo

echo "Build Statistics:"
rch status --stats

echo
echo "Worker Health:"
rch status --workers

echo
echo "Recent Failures:"
rch daemon logs --level error --since "24 hours ago"
```

Schedule with cron:
```cron
0 9 * * * /path/to/rch-daily-report.sh | mail -s "RCH Daily Report" team@example.com
```

## Capacity Planning

### Track Usage Trends

```bash
# Hourly stats collection
*/5 * * * * rch status --json >> /var/log/rch/metrics.jsonl
```

Analyze for patterns:
```bash
# Average slot utilization per hour
cat /var/log/rch/metrics.jsonl | \
    jq -r '[.timestamp, .workers.used_slots/.workers.total_slots] | @csv' | \
    datamash -t, groupby 1 mean 2
```

### Scale Triggers

Consider adding workers when:
- Average slot utilization > 80%
- Build queue regularly > 0
- P95 build wait time > 30s

Consider reducing workers when:
- Average slot utilization < 30%
- Workers frequently idle
- Cost optimization needed
