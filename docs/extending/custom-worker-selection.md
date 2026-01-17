# Custom Worker Selection

This guide explains how to customize RCH's worker selection algorithm.

## Overview

Worker selection determines which remote worker handles a compilation request. The default algorithm considers:
- Available slots (weight: 0.4)
- Speed score (weight: 0.5)
- Project cache locality (weight: 0.1)
- Circuit breaker state (filtering)

## Selection Algorithm

### Default Scoring

In `rchd/src/selection.rs`:

```rust
fn compute_score(worker: &WorkerState, request: &SelectionRequest) -> f64 {
    let slot_score = worker.available_slots() as f64 / worker.total_slots() as f64;
    let speed_score = worker.speed_score / 100.0;
    let cache_score = if worker.has_cached_project(&request.project) { 1.0 } else { 0.0 };

    let weights = SelectionWeights::default();

    slot_score * weights.slot +
    speed_score * weights.speed +
    cache_score * weights.cache
}
```

### Filtering

Workers are filtered before scoring:
1. Circuit breaker must be closed (or half-open with probe budget)
2. Worker must have at least one available slot
3. Worker must have required runtime (Rust, Bun, etc.)
4. Worker must not be draining

## Customization Options

### Configuration-Based Customization

Adjust weights via configuration:

```toml
# ~/.config/rch/config.toml
[selection]
slot_weight = 0.3      # Prefer available capacity
speed_weight = 0.6     # Prefer faster workers
cache_weight = 0.1     # Slight preference for cached projects

# Or prioritize cache for incremental builds
# slot_weight = 0.2
# speed_weight = 0.3
# cache_weight = 0.5
```

### Project-Level Preferences

Specify preferred workers per project:

```toml
# .rch/config.toml
[general]
preferred_workers = ["fast-worker", "local-worker"]
```

### Tag-Based Selection

Filter workers by tags:

```toml
# Worker definition
[[workers]]
id = "gpu-worker"
tags = ["gpu", "cuda"]

# Project config - require GPU
[selection]
required_tags = ["gpu"]

# Or prefer SSD workers
[selection]
preferred_tags = ["ssd"]
```

## Custom Selection Strategies

### Implementing a Custom Strategy

Create a new selection strategy in `rchd/src/selection.rs`:

```rust
pub trait SelectionStrategy: Send + Sync {
    fn select(
        &self,
        workers: &[Arc<WorkerState>],
        request: &SelectionRequest,
    ) -> Option<SelectedWorker>;
}

// Round-robin strategy
pub struct RoundRobinStrategy {
    counter: AtomicUsize,
}

impl SelectionStrategy for RoundRobinStrategy {
    fn select(
        &self,
        workers: &[Arc<WorkerState>],
        request: &SelectionRequest,
    ) -> Option<SelectedWorker> {
        let available: Vec<_> = workers
            .iter()
            .filter(|w| w.can_accept_build())
            .collect();

        if available.is_empty() {
            return None;
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % available.len();
        Some(available[idx].to_selected())
    }
}

// Least-loaded strategy
pub struct LeastLoadedStrategy;

impl SelectionStrategy for LeastLoadedStrategy {
    fn select(
        &self,
        workers: &[Arc<WorkerState>],
        request: &SelectionRequest,
    ) -> Option<SelectedWorker> {
        workers
            .iter()
            .filter(|w| w.can_accept_build())
            .max_by_key(|w| w.available_slots())
            .map(|w| w.to_selected())
    }
}

// Affinity strategy - sticky to workers with project cache
pub struct AffinityStrategy {
    fallback: Box<dyn SelectionStrategy>,
}

impl SelectionStrategy for AffinityStrategy {
    fn select(
        &self,
        workers: &[Arc<WorkerState>],
        request: &SelectionRequest,
    ) -> Option<SelectedWorker> {
        // First, try workers with cached project
        let with_cache: Vec<_> = workers
            .iter()
            .filter(|w| w.can_accept_build() && w.has_cached_project(&request.project))
            .collect();

        if !with_cache.is_empty() {
            // Among cached, prefer least loaded
            return with_cache
                .iter()
                .max_by_key(|w| w.available_slots())
                .map(|w| w.to_selected());
        }

        // Fallback to normal selection
        self.fallback.select(workers, request)
    }
}
```

### Registering Custom Strategies

```rust
// In rchd/src/main.rs or config loading

fn create_selection_strategy(config: &Config) -> Box<dyn SelectionStrategy> {
    match config.selection.strategy.as_str() {
        "round-robin" => Box::new(RoundRobinStrategy::new()),
        "least-loaded" => Box::new(LeastLoadedStrategy),
        "affinity" => Box::new(AffinityStrategy {
            fallback: Box::new(WeightedStrategy::from_config(config)),
        }),
        "weighted" | _ => Box::new(WeightedStrategy::from_config(config)),
    }
}
```

Configuration:
```toml
[selection]
strategy = "affinity"  # or "weighted", "round-robin", "least-loaded"
```

## Advanced Customizations

### Time-Based Selection

Prefer different workers at different times:

```rust
pub struct TimeBasedStrategy {
    daytime_workers: Vec<WorkerId>,
    nighttime_workers: Vec<WorkerId>,
}

impl SelectionStrategy for TimeBasedStrategy {
    fn select(&self, workers: &[Arc<WorkerState>], request: &SelectionRequest) -> Option<SelectedWorker> {
        let hour = chrono::Local::now().hour();
        let preferred = if hour >= 9 && hour < 18 {
            &self.daytime_workers  // Office hours: use cloud workers
        } else {
            &self.nighttime_workers  // Off hours: use office machines
        };

        // Filter to preferred, then select by load
        workers
            .iter()
            .filter(|w| w.can_accept_build() && preferred.contains(&w.id))
            .max_by_key(|w| w.available_slots())
            .map(|w| w.to_selected())
            .or_else(|| {
                // Fallback to any available worker
                workers.iter()
                    .filter(|w| w.can_accept_build())
                    .max_by_key(|w| w.available_slots())
                    .map(|w| w.to_selected())
            })
    }
}
```

### Cost-Aware Selection

If workers have different costs:

```rust
pub struct CostAwareStrategy {
    max_cost_per_build: f64,
}

impl SelectionStrategy for CostAwareStrategy {
    fn select(&self, workers: &[Arc<WorkerState>], request: &SelectionRequest) -> Option<SelectedWorker> {
        // Estimate build cost based on worker rate and estimated duration
        let estimated_duration = estimate_build_duration(&request);

        workers
            .iter()
            .filter(|w| {
                w.can_accept_build() &&
                w.cost_per_hour() * estimated_duration.as_secs_f64() / 3600.0 <= self.max_cost_per_build
            })
            .min_by(|a, b| {
                let cost_a = a.cost_per_hour();
                let cost_b = b.cost_per_hour();
                cost_a.partial_cmp(&cost_b).unwrap()
            })
            .map(|w| w.to_selected())
    }
}
```

Worker config with cost:
```toml
[[workers]]
id = "cheap-worker"
cost_per_hour = 0.05

[[workers]]
id = "fast-worker"
cost_per_hour = 0.50
```

### Locality-Aware Selection

Prefer workers in same region:

```rust
pub struct LocalityStrategy {
    local_region: String,
}

impl SelectionStrategy for LocalityStrategy {
    fn select(&self, workers: &[Arc<WorkerState>], request: &SelectionRequest) -> Option<SelectedWorker> {
        // Tier 1: Same region
        let local = workers.iter()
            .filter(|w| w.can_accept_build() && w.region == self.local_region);

        if let Some(worker) = local.max_by_key(|w| w.available_slots()) {
            return Some(worker.to_selected());
        }

        // Tier 2: Any region
        workers.iter()
            .filter(|w| w.can_accept_build())
            .max_by_key(|w| w.available_slots())
            .map(|w| w.to_selected())
    }
}
```

## Testing Custom Strategies

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affinity_prefers_cached() {
        let workers = vec![
            mock_worker("w1", 10, false),  // 10 slots, no cache
            mock_worker("w2", 5, true),    // 5 slots, has cache
        ];

        let strategy = AffinityStrategy::new();
        let request = SelectionRequest::for_project("my-project");

        let selected = strategy.select(&workers, &request).unwrap();

        // Should select w2 despite fewer slots because it has cache
        assert_eq!(selected.id, "w2");
    }

    #[test]
    fn test_round_robin_distributes() {
        let workers = vec![
            mock_worker("w1", 10, false),
            mock_worker("w2", 10, false),
        ];

        let strategy = RoundRobinStrategy::new();

        let mut selections = HashMap::new();
        for _ in 0..100 {
            let selected = strategy.select(&workers, &default_request()).unwrap();
            *selections.entry(selected.id.clone()).or_insert(0) += 1;
        }

        // Should be roughly equal
        assert!(selections["w1"] > 40);
        assert!(selections["w2"] > 40);
    }
}
```

### Integration Tests

```bash
# Test with mock workers
RCH_MOCK_SSH=1 cargo test -p rchd selection
```

### A/B Testing Strategies

Compare strategies in production:

```toml
[selection]
strategy = "experiment"

[selection.experiment]
control = "weighted"
treatment = "affinity"
treatment_percent = 20
metrics_endpoint = "http://metrics.example.com/api"
```
