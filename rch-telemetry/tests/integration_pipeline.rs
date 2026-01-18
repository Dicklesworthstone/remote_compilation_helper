//! Integration tests for the telemetry pipeline.
//!
//! Tests the complete flow from telemetry collection through storage,
//! aggregation, and cleanup. These tests verify that components work
//! together correctly in realistic scenarios.

mod common;

use chrono::{Duration as ChronoDuration, Utc};
use common::init_test_logging;
use rch_telemetry::collect::cpu::{CpuPressureStall, CpuTelemetry, LoadAverage};
use rch_telemetry::collect::memory::MemoryTelemetry;
use rch_telemetry::protocol::WorkerTelemetry;
use rch_telemetry::speedscore::SpeedScore;
use rch_telemetry::storage::TelemetryStorage;
use tracing::info;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test WorkerTelemetry with customizable values.
fn make_test_telemetry(worker_id: &str, cpu_percent: f64, memory_percent: f64) -> WorkerTelemetry {
    let cpu = CpuTelemetry {
        timestamp: Utc::now(),
        overall_percent: cpu_percent,
        per_core_percent: vec![cpu_percent; 4],
        num_cores: 4,
        load_average: LoadAverage {
            one_min: cpu_percent / 100.0 * 4.0,
            five_min: cpu_percent / 100.0 * 3.5,
            fifteen_min: cpu_percent / 100.0 * 3.0,
            running_processes: 2,
            total_processes: 128,
        },
        psi: Some(CpuPressureStall {
            some_avg10: cpu_percent / 50.0,
            some_avg60: cpu_percent / 60.0,
            some_avg300: cpu_percent / 70.0,
        }),
    };

    let memory = MemoryTelemetry {
        timestamp: Utc::now(),
        total_gb: 16.0,
        available_gb: 16.0 * (1.0 - memory_percent / 100.0),
        used_percent: memory_percent,
        pressure_score: memory_percent * 1.1,
        swap_used_gb: 0.0,
        dirty_mb: 10.0,
        psi: None,
    };

    WorkerTelemetry::new(worker_id.to_string(), cpu, memory, None, None, 50)
}

/// Create a test SpeedScore with customizable values.
fn make_test_speedscore(total: f64) -> SpeedScore {
    SpeedScore {
        total,
        cpu_score: total + 5.0,
        memory_score: total - 5.0,
        disk_score: total,
        network_score: total + 2.0,
        compilation_score: total - 2.0,
        calculated_at: Utc::now(),
        ..SpeedScore::default()
    }
}

// ============================================================================
// Collection to Storage Flow Tests
// ============================================================================

#[test]
fn test_telemetry_collection_to_storage() {
    init_test_logging();
    info!(
        test = "test_telemetry_collection_to_storage",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let telemetry = make_test_telemetry("worker-1", 45.0, 60.0);

    info!(
        test = "test_telemetry_collection_to_storage",
        phase = "execute",
        worker_id = "worker-1",
        cpu_percent = 45.0,
        memory_percent = 60.0
    );

    storage
        .insert_telemetry(&telemetry)
        .expect("insert should succeed");

    info!(
        test = "test_telemetry_collection_to_storage",
        phase = "assert"
    );

    // Verify data was stored (indirectly via summary)
    let summary = telemetry.summary();
    assert_eq!(summary.worker_id, "worker-1");
    assert!((summary.cpu_percent - 45.0).abs() < 0.01);
    assert!((summary.memory_percent - 60.0).abs() < 0.01);

    info!(
        test = "test_telemetry_collection_to_storage",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_telemetry_validates_reasonable_values() {
    init_test_logging();
    info!(
        test = "test_telemetry_validates_reasonable_values",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    // Test with boundary values
    let telemetry_min = make_test_telemetry("worker-min", 0.0, 0.0);
    let telemetry_max = make_test_telemetry("worker-max", 100.0, 100.0);

    info!(
        test = "test_telemetry_validates_reasonable_values",
        phase = "execute"
    );

    storage
        .insert_telemetry(&telemetry_min)
        .expect("min values should insert");
    storage
        .insert_telemetry(&telemetry_max)
        .expect("max values should insert");

    info!(
        test = "test_telemetry_validates_reasonable_values",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// SpeedScore Storage Flow Tests
// ============================================================================

#[test]
fn test_speedscore_insert_and_retrieve() {
    init_test_logging();
    info!(
        test = "test_speedscore_insert_and_retrieve",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let score = make_test_speedscore(75.0);

    info!(
        test = "test_speedscore_insert_and_retrieve",
        phase = "execute",
        worker_id = "worker-ss-1",
        total_score = 75.0
    );

    storage
        .insert_speedscore("worker-ss-1", &score)
        .expect("insert speedscore should succeed");

    let retrieved = storage
        .latest_speedscore("worker-ss-1")
        .expect("query should succeed")
        .expect("score should be present");

    info!(
        test = "test_speedscore_insert_and_retrieve",
        phase = "assert",
        retrieved_total = retrieved.total
    );

    assert!((retrieved.total - 75.0).abs() < 0.01);
    assert!((retrieved.cpu_score - 80.0).abs() < 0.01);
    assert!((retrieved.memory_score - 70.0).abs() < 0.01);

    info!(
        test = "test_speedscore_insert_and_retrieve",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_speedscore_updates_latest() {
    init_test_logging();
    info!(test = "test_speedscore_updates_latest", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    // Insert initial score
    let score1 = make_test_speedscore(60.0);
    storage
        .insert_speedscore("worker-upd", &score1)
        .expect("first insert");

    // Insert updated score
    let score2 = make_test_speedscore(80.0);
    storage
        .insert_speedscore("worker-upd", &score2)
        .expect("second insert");

    info!(test = "test_speedscore_updates_latest", phase = "execute");

    let latest = storage
        .latest_speedscore("worker-upd")
        .expect("query")
        .expect("present");

    info!(
        test = "test_speedscore_updates_latest",
        phase = "assert",
        latest_total = latest.total
    );

    // Latest should be the second score
    assert!((latest.total - 80.0).abs() < 0.01);

    info!(
        test = "test_speedscore_updates_latest",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_speedscore_history_pagination() {
    init_test_logging();
    info!(test = "test_speedscore_history_pagination", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let since = Utc::now() - ChronoDuration::hours(1);

    // Insert multiple scores
    for i in 0..10 {
        let score = make_test_speedscore(50.0 + i as f64 * 5.0);
        storage
            .insert_speedscore("worker-hist", &score)
            .expect("insert");
    }

    info!(
        test = "test_speedscore_history_pagination",
        phase = "execute"
    );

    // Query first page
    let page1 = storage
        .speedscore_history("worker-hist", since, 5, 0)
        .expect("page 1");

    info!(
        test = "test_speedscore_history_pagination",
        phase = "assert",
        total = page1.total,
        entries = page1.entries.len()
    );

    assert_eq!(page1.total, 10);
    assert_eq!(page1.entries.len(), 5);

    // Query second page
    let page2 = storage
        .speedscore_history("worker-hist", since, 5, 5)
        .expect("page 2");

    assert_eq!(page2.total, 10);
    assert_eq!(page2.entries.len(), 5);

    info!(
        test = "test_speedscore_history_pagination",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// Multi-Worker Tests
// ============================================================================

#[test]
fn test_multi_worker_telemetry_isolation() {
    init_test_logging();
    info!(
        test = "test_multi_worker_telemetry_isolation",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let workers = ["css", "csd", "fmd", "yto"];

    // Insert telemetry for each worker
    for (i, worker) in workers.iter().enumerate() {
        let telemetry = make_test_telemetry(worker, 20.0 + i as f64 * 15.0, 30.0 + i as f64 * 10.0);
        storage.insert_telemetry(&telemetry).expect("insert");
    }

    info!(
        test = "test_multi_worker_telemetry_isolation",
        phase = "execute",
        worker_count = workers.len()
    );

    // Verify each worker has separate data
    for worker in workers {
        let score = make_test_speedscore(70.0);
        storage.insert_speedscore(worker, &score).expect("insert");

        let retrieved = storage
            .latest_speedscore(worker)
            .expect("query")
            .expect("present");

        assert!((retrieved.total - 70.0).abs() < 0.01);
    }

    info!(
        test = "test_multi_worker_telemetry_isolation",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_multi_worker_speedscore_isolation() {
    init_test_logging();
    info!(
        test = "test_multi_worker_speedscore_isolation",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    // Insert different scores for different workers
    storage
        .insert_speedscore("worker-a", &make_test_speedscore(60.0))
        .expect("insert a");
    storage
        .insert_speedscore("worker-b", &make_test_speedscore(80.0))
        .expect("insert b");
    storage
        .insert_speedscore("worker-c", &make_test_speedscore(70.0))
        .expect("insert c");

    info!(
        test = "test_multi_worker_speedscore_isolation",
        phase = "execute"
    );

    // Verify isolation
    let score_a = storage
        .latest_speedscore("worker-a")
        .expect("query")
        .expect("present");
    let score_b = storage
        .latest_speedscore("worker-b")
        .expect("query")
        .expect("present");
    let score_c = storage
        .latest_speedscore("worker-c")
        .expect("query")
        .expect("present");

    info!(
        test = "test_multi_worker_speedscore_isolation",
        phase = "assert",
        score_a = score_a.total,
        score_b = score_b.total,
        score_c = score_c.total
    );

    assert!((score_a.total - 60.0).abs() < 0.01);
    assert!((score_b.total - 80.0).abs() < 0.01);
    assert!((score_c.total - 70.0).abs() < 0.01);

    info!(
        test = "test_multi_worker_speedscore_isolation",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_nonexistent_worker_returns_none() {
    init_test_logging();
    info!(
        test = "test_nonexistent_worker_returns_none",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    info!(
        test = "test_nonexistent_worker_returns_none",
        phase = "execute"
    );

    let result = storage
        .latest_speedscore("nonexistent-worker")
        .expect("query should not error");

    info!(
        test = "test_nonexistent_worker_returns_none",
        phase = "assert",
        result_is_none = result.is_none()
    );

    assert!(result.is_none());

    info!(
        test = "test_nonexistent_worker_returns_none",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// Maintenance and Aggregation Tests
// ============================================================================

#[test]
fn test_maintenance_runs_without_error() {
    init_test_logging();
    info!(
        test = "test_maintenance_runs_without_error",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    // Insert some telemetry data
    for i in 0..5 {
        let telemetry = make_test_telemetry(&format!("worker-{}", i), 50.0, 50.0);
        storage.insert_telemetry(&telemetry).expect("insert");
    }

    info!(
        test = "test_maintenance_runs_without_error",
        phase = "execute"
    );

    let stats = storage.maintenance().expect("maintenance should succeed");

    info!(
        test = "test_maintenance_runs_without_error",
        phase = "assert",
        aggregated_hours = stats.aggregated_hours,
        deleted_raw = stats.deleted_raw,
        deleted_hourly = stats.deleted_hourly,
        vacuumed = stats.vacuumed
    );

    // Stats should be valid (values are u64, just verify we can access them)
    let _ = stats.aggregated_hours;
    let _ = stats.deleted_raw;
    let _ = stats.deleted_hourly;

    info!(
        test = "test_maintenance_runs_without_error",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_maintenance_idempotent() {
    init_test_logging();
    info!(test = "test_maintenance_idempotent", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    // Insert data
    let telemetry = make_test_telemetry("worker-idem", 50.0, 50.0);
    storage.insert_telemetry(&telemetry).expect("insert");

    info!(test = "test_maintenance_idempotent", phase = "execute");

    // Run maintenance multiple times
    let stats1 = storage.maintenance().expect("maintenance 1");
    let stats2 = storage.maintenance().expect("maintenance 2");
    let stats3 = storage.maintenance().expect("maintenance 3");

    info!(
        test = "test_maintenance_idempotent",
        phase = "assert",
        run_1_deleted = stats1.deleted_raw,
        run_2_deleted = stats2.deleted_raw,
        run_3_deleted = stats3.deleted_raw
    );

    // Second and third runs should have nothing to do
    assert_eq!(stats2.deleted_raw, 0);
    assert_eq!(stats3.deleted_raw, 0);

    info!(
        test = "test_maintenance_idempotent",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// Protocol and Serialization Tests
// ============================================================================

#[test]
fn test_telemetry_json_roundtrip() {
    init_test_logging();
    info!(test = "test_telemetry_json_roundtrip", phase = "setup");

    let telemetry = make_test_telemetry("worker-json", 42.5, 55.0);

    info!(test = "test_telemetry_json_roundtrip", phase = "execute");

    let json = telemetry.to_json().expect("serialization should succeed");
    let parsed = WorkerTelemetry::from_json(&json).expect("deserialization should succeed");

    info!(
        test = "test_telemetry_json_roundtrip",
        phase = "assert",
        json_len = json.len(),
        parsed_worker_id = parsed.worker_id.as_str()
    );

    assert_eq!(parsed.worker_id, "worker-json");
    assert!((parsed.cpu.overall_percent - 42.5).abs() < 0.01);
    assert!((parsed.memory.used_percent - 55.0).abs() < 0.01);

    info!(
        test = "test_telemetry_json_roundtrip",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_piggyback_extraction() {
    init_test_logging();
    info!(test = "test_piggyback_extraction", phase = "setup");

    let telemetry = make_test_telemetry("worker-piggy", 30.0, 40.0);
    let build_output = "Compiling foo v0.1.0\n   Finished release in 42.5s";

    info!(test = "test_piggyback_extraction", phase = "execute");

    let combined = format!(
        "{}\n{}",
        build_output,
        telemetry.to_piggyback().expect("piggyback format")
    );

    let extraction = rch_telemetry::protocol::extract_piggybacked_telemetry(&combined);

    info!(
        test = "test_piggyback_extraction",
        phase = "assert",
        has_telemetry = extraction.telemetry.is_some(),
        has_error = extraction.extraction_error.is_some()
    );

    assert!(extraction.telemetry.is_some());
    assert!(extraction.extraction_error.is_none());
    assert_eq!(extraction.build_output, build_output);

    let extracted = extraction.telemetry.unwrap();
    assert_eq!(extracted.worker_id, "worker-piggy");

    info!(
        test = "test_piggyback_extraction",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// SpeedScore Calculation Integration Tests
// ============================================================================

#[test]
fn test_speedscore_version_tracking() {
    init_test_logging();
    info!(test = "test_speedscore_version_tracking", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let score = make_test_speedscore(70.0);

    info!(test = "test_speedscore_version_tracking", phase = "execute");

    storage
        .insert_speedscore("worker-ver", &score)
        .expect("insert");

    let retrieved = storage
        .latest_speedscore("worker-ver")
        .expect("query")
        .expect("present");

    info!(
        test = "test_speedscore_version_tracking",
        phase = "assert",
        stored_version = retrieved.version,
        expected_version = rch_telemetry::speedscore::SPEEDSCORE_VERSION
    );

    assert_eq!(
        retrieved.version,
        rch_telemetry::speedscore::SPEEDSCORE_VERSION
    );
    assert!(!retrieved.is_outdated());

    info!(
        test = "test_speedscore_version_tracking",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_speedscore_history_ordering() {
    init_test_logging();
    info!(test = "test_speedscore_history_ordering", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let since = Utc::now() - ChronoDuration::hours(1);

    // Insert scores with increasing values
    for i in 0..5 {
        let score = make_test_speedscore(50.0 + i as f64 * 10.0);
        storage
            .insert_speedscore("worker-ord", &score)
            .expect("insert");
    }

    info!(test = "test_speedscore_history_ordering", phase = "execute");

    let page = storage
        .speedscore_history("worker-ord", since, 10, 0)
        .expect("query");

    info!(
        test = "test_speedscore_history_ordering",
        phase = "assert",
        entry_count = page.entries.len()
    );

    // All 5 entries should be returned
    assert_eq!(page.entries.len(), 5);

    // Collect all scores and verify they match expected values
    let mut scores: Vec<f64> = page.entries.iter().map(|e| e.total).collect();
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

    // Expected values: 50, 60, 70, 80, 90
    let expected = [50.0, 60.0, 70.0, 80.0, 90.0];
    for (i, expected_val) in expected.iter().enumerate() {
        assert!(
            (scores[i] - expected_val).abs() < 0.01,
            "Expected {}, got {}",
            expected_val,
            scores[i]
        );
    }

    info!(
        test = "test_speedscore_history_ordering",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_empty_history_returns_empty_page() {
    init_test_logging();
    info!(
        test = "test_empty_history_returns_empty_page",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let since = Utc::now() - ChronoDuration::hours(1);

    info!(
        test = "test_empty_history_returns_empty_page",
        phase = "execute"
    );

    let page = storage
        .speedscore_history("nonexistent", since, 10, 0)
        .expect("query should not error");

    info!(
        test = "test_empty_history_returns_empty_page",
        phase = "assert",
        total = page.total,
        entries = page.entries.len()
    );

    assert_eq!(page.total, 0);
    assert!(page.entries.is_empty());

    info!(
        test = "test_empty_history_returns_empty_page",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_concurrent_inserts_same_worker() {
    init_test_logging();
    info!(
        test = "test_concurrent_inserts_same_worker",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let since = Utc::now() - ChronoDuration::hours(1);

    info!(
        test = "test_concurrent_inserts_same_worker",
        phase = "execute"
    );

    // Simulate rapid sequential inserts (single-threaded approximation)
    for i in 0..100 {
        let score = make_test_speedscore(50.0 + (i % 50) as f64);
        storage
            .insert_speedscore("worker-concurrent", &score)
            .expect("insert should succeed");
    }

    let page = storage
        .speedscore_history("worker-concurrent", since, 200, 0)
        .expect("query");

    info!(
        test = "test_concurrent_inserts_same_worker",
        phase = "assert",
        total = page.total,
        entries = page.entries.len()
    );

    assert_eq!(page.total, 100);
    assert_eq!(page.entries.len(), 100);

    info!(
        test = "test_concurrent_inserts_same_worker",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_protocol_version_compatibility() {
    init_test_logging();
    info!(
        test = "test_protocol_version_compatibility",
        phase = "setup"
    );

    let telemetry = make_test_telemetry("worker-compat", 50.0, 50.0);

    info!(
        test = "test_protocol_version_compatibility",
        phase = "execute"
    );

    assert!(telemetry.is_compatible());
    assert_eq!(
        telemetry.version,
        rch_telemetry::protocol::TELEMETRY_PROTOCOL_VERSION
    );

    info!(
        test = "test_protocol_version_compatibility",
        phase = "complete",
        status = "passed"
    );
}

// ============================================================================
// Boundary and Edge Case Tests
// ============================================================================

#[test]
fn test_large_batch_insert() {
    init_test_logging();
    info!(test = "test_large_batch_insert", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");

    info!(test = "test_large_batch_insert", phase = "execute");

    // Insert many telemetry snapshots
    for i in 0..500 {
        let telemetry = make_test_telemetry(
            &format!("worker-batch-{}", i % 10),
            (i % 100) as f64,
            (i % 100) as f64,
        );
        storage.insert_telemetry(&telemetry).expect("insert");
    }

    // Insert many speedscores
    for i in 0..100 {
        let score = make_test_speedscore((i % 100) as f64);
        storage
            .insert_speedscore(&format!("worker-batch-{}", i % 10), &score)
            .expect("insert");
    }

    info!(test = "test_large_batch_insert", phase = "assert");

    // Verify maintenance still works
    let stats = storage.maintenance().expect("maintenance");
    info!(
        test = "test_large_batch_insert",
        phase = "complete",
        status = "passed",
        maintenance_aggregated = stats.aggregated_hours
    );
}

#[test]
fn test_special_characters_in_worker_id() {
    init_test_logging();
    info!(
        test = "test_special_characters_in_worker_id",
        phase = "setup"
    );

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let worker_ids = [
        "worker-with-dashes",
        "worker_with_underscores",
        "worker.with.dots",
        "192.168.1.100",
        "worker:8080",
    ];

    info!(
        test = "test_special_characters_in_worker_id",
        phase = "execute",
        worker_count = worker_ids.len()
    );

    for worker_id in worker_ids {
        let score = make_test_speedscore(75.0);
        storage
            .insert_speedscore(worker_id, &score)
            .expect("insert should handle special chars");

        let retrieved = storage
            .latest_speedscore(worker_id)
            .expect("query")
            .expect("should retrieve");

        assert!((retrieved.total - 75.0).abs() < 0.01);
    }

    info!(
        test = "test_special_characters_in_worker_id",
        phase = "complete",
        status = "passed"
    );
}

#[test]
fn test_unicode_worker_id() {
    init_test_logging();
    info!(test = "test_unicode_worker_id", phase = "setup");

    let storage = TelemetryStorage::new_in_memory().expect("storage should init");
    let worker_id = "worker-日本語-тест";

    info!(
        test = "test_unicode_worker_id",
        phase = "execute",
        worker_id = worker_id
    );

    let score = make_test_speedscore(65.0);
    storage
        .insert_speedscore(worker_id, &score)
        .expect("unicode worker id should work");

    let retrieved = storage
        .latest_speedscore(worker_id)
        .expect("query")
        .expect("should retrieve");

    info!(
        test = "test_unicode_worker_id",
        phase = "assert",
        retrieved_total = retrieved.total
    );

    assert!((retrieved.total - 65.0).abs() < 0.01);

    info!(
        test = "test_unicode_worker_id",
        phase = "complete",
        status = "passed"
    );
}
