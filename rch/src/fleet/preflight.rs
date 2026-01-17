//! Preflight checks for worker deployments.

use crate::ui::context::OutputContext;
use anyhow::Result;
use rch_common::WorkerConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreflightResult {
    pub ssh_ok: bool,
    pub disk_space_mb: u64,
    pub disk_ok: bool,
    pub rsync_ok: bool,
    pub zstd_ok: bool,
    pub rustup_ok: bool,
    pub current_version: Option<String>,
    pub issues: Vec<PreflightIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightIssue {
    pub severity: Severity,
    pub check: String,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub worker_id: String,
    pub reachable: bool,
    pub healthy: bool,
    pub version: Option<String>,
    pub issues: Vec<String>,
}

pub async fn run_preflight(
    _worker: &WorkerConfig,
    _ctx: &OutputContext,
) -> Result<PreflightResult> {
    // Simulate successful preflight - real impl would SSH
    Ok(PreflightResult {
        ssh_ok: true,
        disk_space_mb: 10000,
        disk_ok: true,
        rsync_ok: true,
        zstd_ok: true,
        rustup_ok: true,
        current_version: None,
        issues: vec![],
    })
}

pub async fn get_fleet_status(
    workers: &[&WorkerConfig],
    _ctx: &OutputContext,
) -> Result<Vec<WorkerStatus>> {
    Ok(workers
        .iter()
        .map(|w| WorkerStatus {
            worker_id: w.id.0.clone(),
            reachable: true,
            healthy: true,
            version: Some("0.1.0".into()),
            issues: vec![],
        })
        .collect())
}

#[allow(dead_code)]
pub const MIN_DISK_SPACE_MB: u64 = 500;
