//! Versioned, complete scoring evidence from `rch-wkr benchmark`.
//!
//! Worker totals and component scores are presentation, not placement inputs.
//! Send every input used by SpeedScore so the daemon can apply its own current
//! calibration without discarding memory latency or score-only compilations.
//! Missing/failed measurements remain absent; malformed advertised evidence
//! must not be rescued by a legacy `score` or `raw` field in the same response.

use super::{
    CompilationBenchmarkResult, CpuBenchmarkResult, DiskBenchmarkResult, MemoryBenchmarkResult,
    NetworkBenchmarkResult,
};
use crate::speedscore::{BenchmarkResults, SpeedScore};
use serde::{Deserialize, Serialize};

/// The shape and units of scoring evidence, independent of SpeedScore version.
pub const BENCHMARK_REPORT_VERSION: u32 = 1;

/// Raw scoring inputs. Deliberately excludes worker-calculated scores (except
/// the existing compilation benchmark's fallback metric), timestamps, and
/// unused synthetic benchmark fields. None of those can establish placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkReport {
    version: u32,
    cpu: Option<CpuMeasurement>,
    memory: Option<MemoryMeasurement>,
    disk: Option<DiskMeasurement>,
    network: Option<NetworkMeasurement>,
    compilation: Option<CompilationMeasurement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuMeasurement {
    ops_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryMeasurement {
    seq_bandwidth_gbps: f64,
    random_latency_ns: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskMeasurement {
    seq_read_mbps: f64,
    seq_write_mbps: f64,
    random_read_iops: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkMeasurement {
    upload_mbps: f64,
    download_mbps: f64,
    latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompilationMeasurement {
    release_build_ms: u64,
    /// Used only by debug-only/incremental-only configurations with no release
    /// measurement, exactly as in the existing SpeedScore calculation.
    score: f64,
}

/// A report cannot supply a comparable placement measurement.
#[derive(Debug, thiserror::Error)]
pub enum BenchmarkReportError {
    /// The report uses an unknown evidence schema, not merely an old score.
    #[error("unsupported benchmark report version {0}")]
    UnsupportedVersion(u32),
    /// Invalid component inputs cannot be mistaken for an omitted component.
    #[error("invalid {0} measurement in benchmark report")]
    InvalidMeasurement(&'static str),
    /// A successful benchmark report must contain some measured evidence.
    #[error("benchmark report contains no usable measurements")]
    Empty,
}

fn measured(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

impl BenchmarkReport {
    /// Project the exact inputs of the current scoring engine. Default scoring
    /// gives every usable component a positive effective weight and missing
    /// components zero weight. Use that public result to share its availability
    /// policy without exposing internals or mutating diagnostic records.
    #[must_use]
    pub fn from_results(results: &BenchmarkResults) -> Self {
        let weights = SpeedScore::calculate(results).weights;
        Self {
            version: BENCHMARK_REPORT_VERSION,
            cpu: results
                .cpu
                .as_ref()
                .filter(|_| weights.cpu > 0.0)
                .map(|result| CpuMeasurement {
                    ops_per_second: result.ops_per_second,
                }),
            memory: results
                .memory
                .as_ref()
                .filter(|_| weights.memory > 0.0)
                .map(|result| MemoryMeasurement {
                    seq_bandwidth_gbps: result.seq_bandwidth_gbps,
                    random_latency_ns: result.random_latency_ns,
                }),
            disk: results
                .disk
                .as_ref()
                .filter(|_| weights.disk > 0.0)
                .map(|result| DiskMeasurement {
                    seq_read_mbps: result.seq_read_mbps,
                    seq_write_mbps: result.seq_write_mbps,
                    random_read_iops: result.random_read_iops,
                }),
            network: results
                .network
                .as_ref()
                .filter(|_| weights.network > 0.0)
                .map(|result| NetworkMeasurement {
                    upload_mbps: result.upload_mbps,
                    download_mbps: result.download_mbps,
                    latency_ms: result.latency_ms,
                }),
            compilation: results
                .compilation
                .as_ref()
                .filter(|_| weights.compilation > 0.0)
                .map(|result| CompilationMeasurement {
                    release_build_ms: result.release_build_ms,
                    // The score is not used when a release measurement exists.
                    // Do not transport a non-finite, irrelevant synthetic value.
                    score: if result.release_build_ms > 0 {
                        0.0
                    } else {
                        result.score
                    },
                }),
        }
    }

    /// Read the report from the ORIGINAL worker JSON, not a `Value` rebuilt
    /// after duplicate keys have been collapsed. Other top-level presentation
    /// fields are ignored; duplicate reports or duplicate measurement fields
    /// are rejected by the typed deserializer, as are explicit null reports.
    ///
    /// # Errors
    /// A missing, ambiguous or malformed `benchmark_report` field.
    pub fn from_worker_json(output: &str) -> Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        struct WorkerResponse {
            benchmark_report: BenchmarkReport,
        }
        serde_json::from_str::<WorkerResponse>(output).map(|response| response.benchmark_report)
    }

    /// Apply this daemon's calibration to all validated raw inputs. This does
    /// not trust any total, effective weights or component score from a worker.
    ///
    /// # Errors
    /// Unknown evidence versions, invalid present components, or no evidence.
    pub fn recalculate(&self) -> Result<SpeedScore, BenchmarkReportError> {
        if self.version != BENCHMARK_REPORT_VERSION {
            return Err(BenchmarkReportError::UnsupportedVersion(self.version));
        }
        let invalid = BenchmarkReportError::InvalidMeasurement;
        let mut results = BenchmarkResults::new();
        if let Some(cpu) = &self.cpu {
            if !measured(cpu.ops_per_second) {
                return Err(invalid("CPU"));
            }
            results.cpu = Some(CpuBenchmarkResult {
                ops_per_second: cpu.ops_per_second,
                ..Default::default()
            });
        }
        if let Some(memory) = &self.memory {
            if !measured(memory.seq_bandwidth_gbps) || !measured(memory.random_latency_ns) {
                return Err(invalid("memory"));
            }
            results.memory = Some(MemoryBenchmarkResult {
                seq_bandwidth_gbps: memory.seq_bandwidth_gbps,
                random_latency_ns: memory.random_latency_ns,
                ..Default::default()
            });
        }
        if let Some(disk) = &self.disk {
            if !measured(disk.seq_read_mbps)
                || !measured(disk.seq_write_mbps)
                || !measured(disk.random_read_iops)
            {
                return Err(invalid("disk"));
            }
            results.disk = Some(DiskBenchmarkResult {
                seq_read_mbps: disk.seq_read_mbps,
                seq_write_mbps: disk.seq_write_mbps,
                random_read_iops: disk.random_read_iops,
                ..Default::default()
            });
        }
        if let Some(network) = &self.network {
            if !measured(network.upload_mbps)
                || !measured(network.download_mbps)
                || !measured(network.latency_ms)
            {
                return Err(invalid("network"));
            }
            results.network = Some(NetworkBenchmarkResult {
                upload_mbps: network.upload_mbps,
                download_mbps: network.download_mbps,
                latency_ms: network.latency_ms,
                ..Default::default()
            });
        }
        if let Some(compilation) = &self.compilation {
            if !compilation.score.is_finite()
                || compilation.score < 0.0
                || (compilation.release_build_ms == 0 && !measured(compilation.score))
            {
                return Err(invalid("compilation"));
            }
            results.compilation = Some(CompilationBenchmarkResult {
                release_build_ms: compilation.release_build_ms,
                score: compilation.score,
                ..Default::default()
            });
        }
        if results.component_count() == 0 {
            return Err(BenchmarkReportError::Empty);
        }
        Ok(SpeedScore::calculate(&results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> BenchmarkResults {
        BenchmarkResults::new()
            .with_cpu(CpuBenchmarkResult {
                ops_per_second: 250_000.0,
                ..Default::default()
            })
            .with_memory(MemoryBenchmarkResult {
                seq_bandwidth_gbps: 4.0,
                random_latency_ns: 100.0,
                ..Default::default()
            })
            .with_disk(DiskBenchmarkResult {
                seq_read_mbps: 1_000.0,
                seq_write_mbps: 900.0,
                random_read_iops: 100_000.0,
                ..Default::default()
            })
            .with_network(NetworkBenchmarkResult {
                upload_mbps: 500.0,
                download_mbps: 800.0,
                latency_ms: 10.0,
                ..Default::default()
            })
            .with_compilation(CompilationBenchmarkResult {
                release_build_ms: 3_000,
                ..Default::default()
            })
    }

    fn assert_same_score(first: &SpeedScore, second: &SpeedScore) {
        assert_eq!(first.total, second.total);
        assert_eq!(first.cpu_score, second.cpu_score);
        assert_eq!(first.memory_score, second.memory_score);
        assert_eq!(first.disk_score, second.disk_score);
        assert_eq!(first.network_score, second.network_score);
        assert_eq!(first.compilation_score, second.compilation_score);
        assert_eq!(first.weights, second.weights);
        assert_eq!(first.version, second.version);
    }

    fn roundtrip(results: &BenchmarkResults) -> SpeedScore {
        let report = BenchmarkReport::from_results(results);
        let wire = serde_json::json!({
            "score": 100,
            "components": {"memory": 0},
            "raw": {"cpu_ops_per_second": 1},
            "benchmark_report": report,
        })
        .to_string();
        BenchmarkReport::from_worker_json(&wire)
            .unwrap()
            .recalculate()
            .unwrap()
    }

    #[test]
    fn all_components_roundtrip_without_trusting_worker_scores() {
        let results = complete();
        let expected = SpeedScore::calculate(&results);
        let actual = roundtrip(&results);
        assert_same_score(&actual, &expected);
        assert!(actual.weights.memory > 0.0);
        assert!(actual.weights.network > 0.0);
    }

    #[test]
    fn memory_latency_changes_live_score_at_identical_bandwidth() {
        let mut results = complete();
        results.memory.as_mut().unwrap().random_latency_ns = 50.0;
        let fast = roundtrip(&results);
        results.memory.as_mut().unwrap().random_latency_ns = 200.0;
        let slow = roundtrip(&results);
        assert!(fast.memory_score > slow.memory_score);
        assert!(fast.total > slow.total);
    }

    #[test]
    fn optional_components_and_debug_only_compilation_keep_exact_weights() {
        let results = BenchmarkResults::new()
            .with_cpu(complete().cpu.unwrap())
            .with_memory(MemoryBenchmarkResult::default())
            .with_compilation(CompilationBenchmarkResult {
                release_build_ms: 0,
                score: 1500.0,
                ..Default::default()
            });
        assert_same_score(&roundtrip(&results), &SpeedScore::calculate(&results));
        let report = BenchmarkReport::from_results(&results);
        assert!(report.memory.is_none());
        assert!(report.network.is_none());
        assert!(report.compilation.is_some());
        assert!(results.memory.is_some(), "diagnostic records are preserved");
    }

    #[test]
    fn nonfinite_unused_fields_cannot_corrupt_the_scoring_report() {
        let mut results = complete();
        results.cpu.as_mut().unwrap().score = f64::NAN;
        results.compilation.as_mut().unwrap().score = f64::INFINITY;
        assert_same_score(&roundtrip(&results), &SpeedScore::calculate(&results));
        results.cpu.as_mut().unwrap().ops_per_second = f64::NAN;
        let report = BenchmarkReport::from_results(&results);
        assert!(report.cpu.is_none());
        assert_same_score(&roundtrip(&results), &SpeedScore::calculate(&results));
    }

    #[test]
    fn empty_unknown_or_invalid_evidence_is_not_a_successful_measurement() {
        let mut report = BenchmarkReport::from_results(&BenchmarkResults::new());
        assert!(matches!(
            report.recalculate(),
            Err(BenchmarkReportError::Empty)
        ));
        report.version += 1;
        assert!(matches!(
            report.recalculate(),
            Err(BenchmarkReportError::UnsupportedVersion(_))
        ));
        for value in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut report = BenchmarkReport::from_results(&complete());
            report.memory.as_mut().unwrap().random_latency_ns = value;
            assert!(matches!(
                report.recalculate(),
                Err(BenchmarkReportError::InvalidMeasurement("memory"))
            ));
        }
    }

    #[test]
    fn typed_decode_rejects_ambiguous_or_partial_present_measurements() {
        for wire in [
            r#"{}"#,
            r#"{"benchmark_report":null,"score":99}"#,
            r#"{"benchmark_report":{"version":1,"memory":{"seq_bandwidth_gbps":4}}}"#,
            r#"{"benchmark_report":{"version":1,"version":1,"cpu":{"ops_per_second":250000}}}"#,
            r#"{"benchmark_report":{"version":1,"cpu":{"ops_per_second":1,"ops_per_second":250000}}}"#,
            r#"{"benchmark_report":{"version":1,"cpu":{"ops_per_second":250000},"cpu":null}}"#,
            r#"{"benchmark_report":{"version":1,"cpu":{"ops_per_second":250000}},"benchmark_report":{"version":1,"cpu":{"ops_per_second":1}}}"#,
            r#"{"benchmark_report":{"version":1,"cpu":{"ops_per_second":1e9999}}}"#,
        ] {
            assert!(BenchmarkReport::from_worker_json(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn every_component_subset_preserves_the_current_calibration() {
        for mask in 1u8..32 {
            let mut results = complete();
            if mask & 1 == 0 {
                results.cpu = None;
            }
            if mask & 2 == 0 {
                results.memory = None;
            }
            if mask & 4 == 0 {
                results.disk = None;
            }
            if mask & 8 == 0 {
                results.network = None;
            }
            if mask & 16 == 0 {
                results.compilation = None;
            }
            assert_same_score(&roundtrip(&results), &SpeedScore::calculate(&results));
        }
    }
}
