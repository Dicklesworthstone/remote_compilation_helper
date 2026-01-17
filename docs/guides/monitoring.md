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

Import the provided Grafana dashboard or create your own:

Key panels:
1. **Build throughput** - Builds per minute by worker
2. **Build duration** - P50, P95, P99 latency
3. **Worker health** - Status heatmap
4. **Slot utilization** - Used vs available slots
5. **Transfer rates** - MB/s to workers
6. **Circuit breaker events** - Timeline of state changes

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
