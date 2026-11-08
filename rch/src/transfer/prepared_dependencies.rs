//! Qualified dependency preparation uses the ordinary resource supervisors,
//! but has its own phase identity and never consumes workload completion.
use super::*;
use rch_common::prepared_dependencies::{PreparedDependencyAttestation, PreparedDependencyRequest};

#[derive(Clone)]
pub(super) struct PreparedDependencyExecution {
    pub(super) request_digest: String,
    pub(super) attestation_digest: String,
}

/// The request is stdin data, outside every nested exec argument. In
/// particular, a large source manifest must not become the disk supervisor's
/// `sh -lc` argument. The surrounding finite activity frame uploads the whole
/// program before any source operation starts.
fn request_stdin(command: &str, request: &PreparedDependencyRequest) -> Result<String> {
    request.validate()?;
    let payload = serde_json::to_string(request)?;
    let delimiter = format!("RCH_PREPARED_REQUEST_{}", blake3::hash(payload.as_bytes()));
    Ok(format!(
        "{{\n{command}\n}} <<'{delimiter}'\n{payload}\n{delimiter}\n"
    ))
}

impl TransferPipeline {
    pub(crate) fn dependency_runtime(&self) -> Option<&'static str> {
        match self.compilation_kind {
            Some(CompilationKind::Tsc) => Some("node"),
            Some(CompilationKind::BunTest | CompilationKind::BunTypecheck) => Some("bun"),
            _ => None,
        }
    }

    fn prepared_execution_timeout_seconds(&self) -> u64 {
        if let Some(deadline) = self.prepared_execution_deadline {
            // The admission method rejects an already exhausted budget. Keep
            // a deadline that expires while constructing the command enabled:
            // zero means unlimited to the existing remote supervisor.
            return rch_common::timing::ceil_seconds(
                deadline.saturating_duration_since(TokioInstant::now()),
            )
            .max(1);
        }
        if self.compilation_config.external_timeout_enabled() {
            self.compilation_config
                .timeout_for_kind(self.compilation_kind)
                .as_secs()
        } else {
            0
        }
    }

    /// Retained inspection is read-only and precedes the initial namespace
    /// barrier. It can return an existing verified inventory, never adopt one.
    pub(crate) fn inspect_prepared_dependencies_script(
        &self,
        request: &PreparedDependencyRequest,
        timeout: Duration,
    ) -> Result<String> {
        let command = self.prepared_dependency_command("inspect")?;
        let environment = self.build_remote_env_plan(&self.remote_path());
        let command = format!("{}{command}", environment.env_prefix.prefix);
        let script = request_stdin(&command, request)?;
        Ok(source_activity_bounded_script(
            self.source_authority_prefix
                .as_deref()
                .context("prepared dependencies require source ownership")?,
            &script,
            timeout,
        ))
    }

    fn prepared_dependency_command(&self, mode: &str) -> Result<String> {
        anyhow::ensure!(
            !self.worker_platform.is_windows(),
            "qualified dependency preparation requires a Unix worker"
        );
        let runtime = self
            .dependency_runtime()
            .context("command has no Node dependency preparation policy")?;
        let project = escape(Cow::Owned(self.remote_path()));
        Ok(format!(
            "rch-wkr prepare-proof --mode {mode} --project {project} --runtime {runtime}"
        ))
    }

    /// Preparation is an owned source activity, not another execution of the
    /// admitted build. Its disk receipt and process group are independent of
    /// the workload's durable completion receipt and daemon build identity.
    pub(crate) fn dependency_preparation_phase(&mut self) -> Result<(Self, Duration)> {
        anyhow::ensure!(
            self.source_authority_prefix.is_some() && self.dependency_runtime().is_some(),
            "qualified preparation requires a classified command and source grant"
        );
        anyhow::ensure!(
            self.disk_budget
                .is_none_or(|budget| budget.warm_policy.is_none()),
            "Node dependency preparation cannot consume a Cargo warm-pool reservation"
        );
        let configured_timeout = self
            .compilation_config
            .timeout_for_kind(self.compilation_kind);
        if self.prepared_execution_deadline.is_none()
            && self.compilation_config.external_timeout_enabled()
            && !configured_timeout.is_zero()
        {
            self.prepared_execution_deadline = Some(
                TokioInstant::now()
                    .checked_add(configured_timeout)
                    .context("dependency preparation deadline exceeds the clock range")?,
            );
        }
        self.ensure_prepared_execution_time()?;
        let timeout = self
            .prepared_execution_deadline
            .map(|deadline| deadline.saturating_duration_since(TokioInstant::now()))
            .unwrap_or(rch_common::timing::MAX_CONTROL_TIMEOUT)
            .min(rch_common::timing::MAX_CONTROL_TIMEOUT);
        let mut phase = self.clone();
        phase.deadline_marker = format!("RCH_EXTERNAL_DEADLINE:{}", uuid::Uuid::new_v4());
        phase.build_id = None;
        phase.recovery_completion = None;
        // The finite-RPC supervisor pins this group and drains it before the
        // activity lease can be released. A standalone disk guardian would
        // setsid() out of that group and leave a parent-loss teardown race.
        phase.source_activity_owns_execution = true;
        phase.prepared_dependencies = None;
        phase.prepared_execution_deadline = Some(TokioInstant::now() + timeout);
        Ok((phase, timeout))
    }

    pub(crate) fn install_prepared_dependencies_script(
        &self,
        request: &PreparedDependencyRequest,
        timeout: Duration,
    ) -> Result<String> {
        anyhow::ensure!(
            self.build_id.is_none()
                && self.recovery_completion.is_none()
                && self.source_activity_owns_execution,
            "dependency preparation must not reuse workload completion identity"
        );
        let command = self.prepared_dependency_command("install")?;
        let command = self.build_remote_command_with_preparation(&command, None, false);
        let script = request_stdin(&command, request)?;
        Ok(source_activity_bounded_script(
            self.source_authority_prefix
                .as_deref()
                .context("prepared dependencies require source ownership")?,
            &script,
            timeout,
        ))
    }

    /// Charge the complete preparation peak before the next phase establishes
    /// a new filesystem baseline. Otherwise those newly installed files would
    /// silently disappear from the job's cumulative allocation allowance.
    pub(crate) fn confirm_dependency_preparation(&self, result: &CommandResult) -> Result<u64> {
        self.ensure_remote_disk_budget(result)?;
        anyhow::ensure!(
            result.success(),
            "qualified dependency preparation failed (exit {}): {}",
            result.exit_code,
            result.stderr.trim()
        );
        if self.disk_budget.is_none() {
            return Ok(0);
        }
        let mut peak = None;
        for usage in result
            .stderr
            .split_inclusive('\n')
            .filter_map(|line| self.parse_complete_disk_usage(line))
        {
            anyhow::ensure!(
                usage.exit_code == Some(0)
                    && peak.is_none_or(|previous| previous == usage.peak_growth_bytes),
                "dependency preparation disk receipts disagree"
            );
            peak = Some(usage.peak_growth_bytes);
        }
        peak.context("dependency preparation has no complete disk usage receipt")
    }

    pub(crate) fn accept_prepared_dependencies(
        &mut self,
        request: &PreparedDependencyRequest,
        attestation: &PreparedDependencyAttestation,
        preparation_growth_bytes: u64,
    ) -> Result<()> {
        attestation.validate_for(request)?;
        self.ensure_prepared_execution_time()?;
        if let Some(mut budget) = self.disk_budget {
            budget.max_growth_bytes = budget
                .max_growth_bytes
                .checked_sub(preparation_growth_bytes)
                .filter(|remaining| *remaining > 0)
                .context("dependency preparation exhausted the admitted disk growth budget")?;
            self.disk_budget = Some(budget);
        }
        self.prepared_dependencies = Some(PreparedDependencyExecution {
            request_digest: request.digest()?,
            attestation_digest: attestation.digest()?,
        });
        Ok(())
    }

    pub(crate) fn ensure_prepared_execution_time(&self) -> Result<()> {
        anyhow::ensure!(
            self.prepared_execution_deadline
                .is_none_or(|deadline| TokioInstant::now() < deadline),
            "dependency preparation exhausted the workload deadline"
        );
        Ok(())
    }
}
