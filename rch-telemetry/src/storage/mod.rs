//! Persistent storage for telemetry snapshots and SpeedScore history.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, warn};

use crate::protocol::{TestRunRecord, TestRunStats, WorkerTelemetry};
use crate::speedscore::SpeedScore;

mod schema;

/// Storage maintenance statistics.
#[derive(Debug, Clone, Copy)]
pub struct MaintenanceStats {
    pub aggregated_hours: u64,
    pub deleted_raw: u64,
    pub deleted_hourly: u64,
    pub vacuumed: bool,
}

/// Page of SpeedScore history entries.
#[derive(Debug, Clone)]
pub struct SpeedScoreHistoryPage {
    pub total: u64,
    pub entries: Vec<SpeedScore>,
}

/// SQLite-backed telemetry storage.
pub struct TelemetryStorage {
    conn: Mutex<Connection>,
    db_path: Option<PathBuf>,
    retention_days: u32,
    aggregate_after_hours: u32,
    hourly_retention_days: u32,
    vacuum_threshold_mb: u64,
}

impl TelemetryStorage {
    /// Create a new telemetry storage using a file-backed SQLite database.
    pub fn new(
        path: &Path,
        retention_days: u32,
        aggregate_after_hours: u32,
        hourly_retention_days: u32,
        vacuum_threshold_mb: u64,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create storage directory {:?}", parent))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open telemetry database at {:?}", path))?;

        // Configure SQLite for optimal performance and reliability
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA wal_autocheckpoint=1000;
             PRAGMA foreign_keys=ON;",
        )
        .context("Failed to configure SQLite WAL mode")?;

        // Set busy timeout for concurrent access (5 seconds)
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .context("Failed to set SQLite busy timeout")?;

        let storage = Self {
            conn: Mutex::new(conn),
            db_path: Some(path.to_path_buf()),
            retention_days,
            aggregate_after_hours,
            hourly_retention_days,
            vacuum_threshold_mb,
        };
        storage.run_migrations()?;
        Ok(storage)
    }

    /// Create an in-memory storage instance for tests.
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Failed to open in-memory DB")?;
        conn.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;")
            .context("Failed to configure in-memory DB")?;

        let storage = Self {
            conn: Mutex::new(conn),
            db_path: None,
            retention_days: 30,
            aggregate_after_hours: 24,
            hourly_retention_days: 365,
            vacuum_threshold_mb: 0,
        };
        storage.run_migrations()?;
        Ok(storage)
    }

    /// Insert a telemetry snapshot.
    pub fn insert_telemetry(&self, telemetry: &WorkerTelemetry) -> Result<()> {
        let disk = telemetry.disk.as_ref();
        let network = telemetry.network.as_ref();

        let memory_total_mb = (telemetry.memory.total_gb * 1024.0).round() as i64;
        let memory_available_mb = (telemetry.memory.available_gb * 1024.0).round() as i64;

        let disk_iops = disk.map(|d| d.devices.iter().map(|m| m.iops).sum::<f64>());

        let conn = self.conn.lock().expect("telemetry db lock");
        conn.execute(
            "INSERT INTO telemetry_snapshots (
                worker_id, timestamp,
                cpu_percent, cpu_user_percent, cpu_system_percent, cpu_iowait_percent,
                load_avg_1m, load_avg_5m, load_avg_15m,
                memory_total_mb, memory_available_mb, memory_used_percent, swap_used_percent,
                disk_read_mbps, disk_write_mbps, disk_iops, disk_utilization_percent,
                network_rx_mbps, network_tx_mbps, network_error_rate
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                telemetry.worker_id.as_str(),
                telemetry.timestamp.timestamp(),
                telemetry.cpu.overall_percent,
                Option::<f64>::None,
                Option::<f64>::None,
                Option::<f64>::None,
                telemetry.cpu.load_average.one_min,
                telemetry.cpu.load_average.five_min,
                telemetry.cpu.load_average.fifteen_min,
                memory_total_mb,
                memory_available_mb,
                telemetry.memory.used_percent,
                Option::<f64>::None,
                disk.map(|d| d.total_read_throughput_mbps),
                disk.map(|d| d.total_write_throughput_mbps),
                disk_iops,
                disk.map(|d| d.max_io_utilization_pct),
                network.map(|n| n.total_rx_mbps),
                network.map(|n| n.total_tx_mbps),
                network.map(|n| n.total_error_rate),
            ],
        )?;

        Ok(())
    }

    /// Insert a SpeedScore and update the latest cache.
    pub fn insert_speedscore(&self, worker_id: &str, score: &SpeedScore) -> Result<()> {
        let mut conn = self.conn.lock().expect("telemetry db lock");
        let tx = conn.transaction()?;

        let raw_json = serde_json::to_string(score).ok();

        tx.execute(
            "INSERT INTO speedscore_history (
                worker_id, measured_at, total_score, cpu_score, memory_score, disk_score,
                network_score, compilation_score, raw_results, algorithm_version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                worker_id,
                score.calculated_at.timestamp(),
                score.total,
                score.cpu_score,
                score.memory_score,
                score.disk_score,
                score.network_score,
                score.compilation_score,
                raw_json,
                score.version,
            ],
        )?;

        let id = tx.last_insert_rowid();

        tx.execute(
            "INSERT OR REPLACE INTO speedscore_latest (worker_id, speedscore_id, total_score, measured_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![worker_id, id, score.total, score.calculated_at.timestamp()],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Insert a test run record.
    pub fn insert_test_run(&self, record: &TestRunRecord) -> Result<()> {
        let conn = self.conn.lock().expect("telemetry db lock");
        conn.execute(
            "INSERT INTO test_runs (
                project_id, worker_id, command, kind, exit_code, duration_ms, completed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.project_id,
                record.worker_id,
                record.command,
                record.kind,
                record.exit_code,
                record.duration_ms as i64,
                record.completed_at.timestamp(),
            ],
        )?;
        Ok(())
    }

    /// Fetch aggregate test run statistics.
    pub fn test_run_stats(&self) -> Result<TestRunStats> {
        let conn = self.conn.lock().expect("telemetry db lock");
        let (total, passed, failed, build_error, avg_duration): (i64, i64, i64, i64, Option<f64>) =
            conn.query_row(
                "SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) as passed,
                    SUM(CASE WHEN exit_code = 101 THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN exit_code = 1 THEN 1 ELSE 0 END) as build_error,
                    AVG(duration_ms) as avg_duration
                 FROM test_runs",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<f64>>(4)?,
                    ))
                },
            )?;

        let mut stats = TestRunStats {
            total_runs: total.max(0) as u64,
            passed_runs: passed.max(0) as u64,
            failed_runs: failed.max(0) as u64,
            build_error_runs: build_error.max(0) as u64,
            avg_duration_ms: avg_duration.unwrap_or(0.0).round() as u64,
            runs_by_kind: HashMap::new(),
        };

        let mut stmt = conn.prepare_cached("SELECT kind, COUNT(*) FROM test_runs GROUP BY kind")?;
        let rows = stmt.query_map([], |row| {
            let kind: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((kind, count))
        })?;

        for row in rows {
            let (kind, count) = row?;
            stats.runs_by_kind.insert(kind, count.max(0) as u64);
        }

        Ok(stats)
    }

    /// Fetch the latest SpeedScore for a worker.
    pub fn latest_speedscore(&self, worker_id: &str) -> Result<Option<SpeedScore>> {
        let conn = self.conn.lock().expect("telemetry db lock");
        let mut stmt = conn.prepare_cached(
            "SELECT h.raw_results FROM speedscore_latest l
             JOIN speedscore_history h ON l.speedscore_id = h.id
             WHERE l.worker_id = ?1",
        )?;

        let raw: Option<String> = stmt
            .query_row(params![worker_id], |row| row.get(0))
            .optional()?;

        if let Some(raw) = raw {
            let parsed =
                serde_json::from_str(&raw).context("Failed to deserialize SpeedScore JSON")?;
            return Ok(Some(parsed));
        }

        Ok(None)
    }

    /// Fetch SpeedScore history for a worker since a cutoff timestamp.
    pub fn speedscore_history(
        &self,
        worker_id: &str,
        since: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<SpeedScoreHistoryPage> {
        let conn = self.conn.lock().expect("telemetry db lock");
        let since_ts = since.timestamp();

        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM speedscore_history WHERE worker_id = ?1 AND measured_at >= ?2",
            params![worker_id, since_ts],
            |row| row.get(0),
        )?;
        let total = total as u64;

        let mut stmt = conn.prepare_cached(
            "SELECT raw_results FROM speedscore_history
             WHERE worker_id = ?1 AND measured_at >= ?2
             ORDER BY measured_at DESC
             LIMIT ?3 OFFSET ?4",
        )?;

        let mut entries = Vec::new();
        let rows = stmt.query_map(
            params![worker_id, since_ts, limit as i64, offset as i64,],
            |row| row.get::<_, Option<String>>(0),
        )?;

        for row in rows {
            let raw = row?;
            let Some(raw) = raw else {
                continue;
            };
            let parsed: SpeedScore =
                serde_json::from_str(&raw).context("Failed to deserialize SpeedScore JSON")?;
            entries.push(parsed);
        }

        Ok(SpeedScoreHistoryPage { total, entries })
    }

    /// Run periodic maintenance: aggregate old telemetry and prune expired data.
    pub fn maintenance(&self) -> Result<MaintenanceStats> {
        let aggregated_hours = self.aggregate_old_telemetry()?;
        let deleted_raw = self.cleanup_raw()?;
        let deleted_hourly = self.cleanup_hourly()?;
        let vacuumed = self.maybe_vacuum()?;

        Ok(MaintenanceStats {
            aggregated_hours,
            deleted_raw,
            deleted_hourly,
            vacuumed,
        })
    }

    fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().expect("telemetry db lock");
        conn.execute_batch(schema::SCHEMA)
            .context("Failed to apply telemetry schema")?;
        Ok(())
    }

    fn aggregate_old_telemetry(&self) -> Result<u64> {
        if self.aggregate_after_hours == 0 {
            return Ok(0);
        }

        let cutoff = Utc::now() - ChronoDuration::hours(self.aggregate_after_hours as i64);
        let cutoff_ts = cutoff.timestamp();

        let conn = self.conn.lock().expect("telemetry db lock");
        let inserted = conn.execute(
            "INSERT OR REPLACE INTO telemetry_hourly (
                worker_id, hour_timestamp, sample_count,
                cpu_percent_avg, cpu_percent_max, memory_used_percent_avg, disk_utilization_avg
            )
            SELECT
                worker_id,
                (timestamp / 3600) * 3600 AS hour_ts,
                COUNT(*),
                AVG(cpu_percent),
                MAX(cpu_percent),
                AVG(memory_used_percent),
                AVG(disk_utilization_percent)
            FROM telemetry_snapshots
            WHERE timestamp <= ?1
            GROUP BY worker_id, hour_ts",
            params![cutoff_ts],
        )? as u64;

        let _deleted = conn.execute(
            "DELETE FROM telemetry_snapshots WHERE timestamp <= ?1",
            params![cutoff_ts],
        )? as u64;

        Ok(inserted)
    }

    fn cleanup_raw(&self) -> Result<u64> {
        if self.retention_days == 0 {
            return Ok(0);
        }

        let cutoff = Utc::now() - ChronoDuration::days(self.retention_days as i64);
        let cutoff_ts = cutoff.timestamp();

        let conn = self.conn.lock().expect("telemetry db lock");
        let rows = conn.execute(
            "DELETE FROM telemetry_snapshots WHERE timestamp < ?1",
            params![cutoff_ts],
        )? as u64;

        Ok(rows)
    }

    fn cleanup_hourly(&self) -> Result<u64> {
        if self.hourly_retention_days == 0 {
            return Ok(0);
        }

        let cutoff = Utc::now() - ChronoDuration::days(self.hourly_retention_days as i64);
        let cutoff_ts = cutoff.timestamp();

        let conn = self.conn.lock().expect("telemetry db lock");
        let rows = conn.execute(
            "DELETE FROM telemetry_hourly WHERE hour_timestamp < ?1",
            params![cutoff_ts],
        )? as u64;

        Ok(rows)
    }

    fn maybe_vacuum(&self) -> Result<bool> {
        let Some(path) = self.db_path.as_ref() else {
            return Ok(false);
        };
        if self.vacuum_threshold_mb == 0 {
            return Ok(false);
        }

        let size_mb = match std::fs::metadata(path) {
            Ok(meta) => meta.len() as f64 / 1_048_576.0,
            Err(err) => {
                warn!("Failed to stat telemetry DB {:?}: {}", path, err);
                return Ok(false);
            }
        };

        if size_mb < self.vacuum_threshold_mb as f64 {
            return Ok(false);
        }

        let conn = self.conn.lock().expect("telemetry db lock");
        debug!("Running VACUUM on telemetry DB (size {:.1} MB)", size_mb);
        conn.execute_batch("VACUUM")?;
        Ok(true)
    }

    /// Check database integrity using SQLite's built-in integrity check.
    /// Returns Ok(()) if the database is healthy, or an error with details.
    pub fn integrity_check(&self) -> Result<()> {
        let conn = self.conn.lock().expect("telemetry db lock");
        let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;

        if result == "ok" {
            Ok(())
        } else {
            anyhow::bail!("Database integrity check failed: {}", result)
        }
    }

    /// Get database statistics for diagnostics.
    pub fn stats(&self) -> Result<StorageStats> {
        let conn = self.conn.lock().expect("telemetry db lock");

        let telemetry_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM telemetry_snapshots", [], |row| {
                row.get(0)
            })?;
        let hourly_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM telemetry_hourly", [], |row| {
                row.get(0)
            })?;
        let speedscore_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM speedscore_history", [], |row| {
                row.get(0)
            })?;
        let test_run_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM test_runs", [], |row| row.get(0))?;

        let db_size_bytes = self
            .db_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(StorageStats {
            telemetry_snapshots: telemetry_count as u64,
            hourly_aggregates: hourly_count as u64,
            speedscore_entries: speedscore_count as u64,
            test_runs: test_run_count as u64,
            db_size_bytes,
        })
    }
}

/// Database statistics for diagnostics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub telemetry_snapshots: u64,
    pub hourly_aggregates: u64,
    pub speedscore_entries: u64,
    pub test_runs: u64,
    pub db_size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::cpu::{CpuTelemetry, LoadAverage};
    use crate::collect::memory::MemoryTelemetry;

    fn make_telemetry(worker_id: &str) -> WorkerTelemetry {
        let cpu = CpuTelemetry {
            timestamp: Utc::now(),
            overall_percent: 42.0,
            per_core_percent: vec![42.0],
            num_cores: 1,
            load_average: LoadAverage {
                one_min: 0.5,
                five_min: 0.3,
                fifteen_min: 0.2,
                running_processes: 1,
                total_processes: 100,
            },
            psi: None,
        };

        let memory = MemoryTelemetry {
            timestamp: Utc::now(),
            total_gb: 16.0,
            available_gb: 8.0,
            used_percent: 50.0,
            pressure_score: 55.0,
            swap_used_gb: 0.0,
            dirty_mb: 0.0,
            psi: None,
        };

        WorkerTelemetry::new(worker_id.to_string(), cpu, memory, None, None, 50)
    }

    #[test]
    fn test_insert_and_latest_speedscore() {
        let storage = TelemetryStorage::new_in_memory().expect("storage");

        let score = SpeedScore {
            total: 80.0,
            cpu_score: 90.0,
            memory_score: 70.0,
            disk_score: 75.0,
            network_score: 85.0,
            compilation_score: 78.0,
            calculated_at: Utc::now(),
            ..SpeedScore::default()
        };

        storage
            .insert_speedscore("worker-1", &score)
            .expect("insert speedscore");

        let latest = storage
            .latest_speedscore("worker-1")
            .expect("latest speedscore")
            .expect("score present");

        assert!((latest.total - 80.0).abs() < 0.01);
        assert_eq!(latest.version, score.version);
    }

    #[test]
    fn test_insert_telemetry_snapshot() {
        let storage = TelemetryStorage::new_in_memory().expect("storage");
        let telemetry = make_telemetry("worker-telemetry");

        storage
            .insert_telemetry(&telemetry)
            .expect("insert telemetry");

        let conn = storage.conn.lock().expect("telemetry db lock");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM telemetry_snapshots WHERE worker_id = ?1",
                params!["worker-telemetry"],
                |row| row.get(0),
            )
            .expect("count query");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_test_run_and_stats() {
        let storage = TelemetryStorage::new_in_memory().expect("storage");
        let record = TestRunRecord {
            project_id: "proj".to_string(),
            worker_id: "worker-1".to_string(),
            command: "cargo test".to_string(),
            kind: "cargo_test".to_string(),
            exit_code: 0,
            duration_ms: 1234,
            completed_at: Utc::now(),
        };

        storage.insert_test_run(&record).expect("insert test run");
        let stats = storage.test_run_stats().expect("test run stats");

        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.passed_runs, 1);
        assert_eq!(stats.failed_runs, 0);
        assert_eq!(stats.build_error_runs, 0);
        assert!(stats.avg_duration_ms > 0);
        assert_eq!(stats.runs_by_kind.get("cargo_test"), Some(&1));
    }
}
