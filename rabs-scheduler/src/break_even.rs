//! Predicted completion + the transfer break-even score (bead I009;
//! plan §84; risk R23).
//!
//! The scheduler's remote-or-local question answered as pure integer
//! arithmetic:
//!
//! ```text
//! remote_completion = queue delay + missing-input transfer
//!                   + toolchain materialization + execution
//!                   + output return + reliability risk penalty
//!                   + pressure penalty
//! local_completion  = local queue + local execution
//! ```
//!
//! The decision compares the two WITH the uncertainty margin on the
//! remote side (uncertain remote estimates must beat local by more).
//! The R23 shape falls out: tiny actions against cold remote inputs
//! run locally; long or widely-shared actions absorb moderate
//! transfer cost. Every decision produces a receipt with the full
//! term breakdown — the numbers `rch why` shows.

/// Inputs to one break-even evaluation (all durations in ms, sizes in
/// bytes, ratios in permille — integers only, fully deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakEvenInputs {
    /// Local queue delay estimate.
    pub local_queue_ms: u64,
    /// Local execution estimate.
    pub local_exec_ms: u64,
    /// Remote queue delay estimate.
    pub remote_queue_ms: u64,
    /// Remote execution estimate.
    pub remote_exec_ms: u64,
    /// Total input bytes the action needs.
    pub input_bytes: u64,
    /// Fraction of inputs already on the worker, permille.
    pub inputs_already_local_permille: u16,
    /// Path throughput, bytes per millisecond.
    pub path_bytes_per_ms: u64,
    /// Path round-trip time.
    pub path_rtt_ms: u64,
    /// Toolchain materialization cost (0 when staged).
    pub toolchain_materialization_ms: u64,
    /// Output bytes to return.
    pub output_bytes: u64,
    /// Retrieval-reliability risk penalty.
    pub reliability_penalty_ms: u64,
    /// Worker pressure penalty.
    pub pressure_penalty_ms: u64,
    /// Estimate uncertainty, permille (I005): scales the margin.
    pub uncertainty_permille: u16,
    /// Subscribers wanting this action (sharing amortizes transfer).
    pub subscriber_count: u32,
}

/// The receipt: every term, both totals, and the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakEvenReceipt {
    /// Missing-input transfer time.
    pub transfer_ms: u64,
    /// Output return time.
    pub output_return_ms: u64,
    /// Predicted remote completion.
    pub remote_completion_ms: u64,
    /// Predicted local completion.
    pub local_completion_ms: u64,
    /// The uncertainty margin applied to the remote side.
    pub margin_ms: u64,
    /// The decision.
    pub decision: BreakEvenDecision,
}

/// Remote or local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakEvenDecision {
    /// Remote wins even with the margin.
    ExecuteRemote,
    /// Local wins (or remote fails the margin): TRANSFER_BREAK_EVEN_LOCAL.
    ExecuteLocal,
}

/// Evaluate the break-even.
#[must_use]
pub fn evaluate_break_even(inputs: &BreakEvenInputs) -> BreakEvenReceipt {
    let throughput = inputs.path_bytes_per_ms.max(1);
    // Missing-input transfer, amortized across subscribers (a widely
    // shared action pays the transfer once for many consumers).
    let missing_permille = 1000_u64.saturating_sub(u64::from(inputs.inputs_already_local_permille));
    let missing_bytes = inputs.input_bytes.saturating_mul(missing_permille) / 1000;
    let sharing = u64::from(inputs.subscriber_count.max(1));
    let transfer_ms = (missing_bytes / throughput + inputs.path_rtt_ms) / sharing;
    let output_return_ms = inputs.output_bytes / throughput + inputs.path_rtt_ms;

    let remote_completion_ms = inputs.remote_queue_ms
        + transfer_ms
        + inputs.toolchain_materialization_ms
        + inputs.remote_exec_ms
        + output_return_ms
        + inputs.reliability_penalty_ms
        + inputs.pressure_penalty_ms;
    let local_completion_ms = inputs.local_queue_ms + inputs.local_exec_ms;

    // Uncertain remote estimates must beat local by MORE: margin =
    // remote * uncertainty / 1000.
    let margin_ms =
        remote_completion_ms.saturating_mul(u64::from(inputs.uncertainty_permille)) / 1000;
    let decision = if remote_completion_ms + margin_ms < local_completion_ms {
        BreakEvenDecision::ExecuteRemote
    } else {
        BreakEvenDecision::ExecuteLocal
    };
    BreakEvenReceipt {
        transfer_ms,
        output_return_ms,
        remote_completion_ms,
        local_completion_ms,
        margin_ms,
        decision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny action against a cold remote (the R23 canonical case).
    fn tiny_cold() -> BreakEvenInputs {
        BreakEvenInputs {
            local_queue_ms: 0,
            local_exec_ms: 400, // a small crate compiles fast locally
            remote_queue_ms: 50,
            remote_exec_ms: 150,
            input_bytes: 200 << 20, // 200 MiB of cold inputs
            inputs_already_local_permille: 0,
            path_bytes_per_ms: 100 << 10, // ~100 MiB/s
            path_rtt_ms: 20,
            toolchain_materialization_ms: 500,
            output_bytes: 1 << 20,
            reliability_penalty_ms: 10,
            pressure_penalty_ms: 0,
            uncertainty_permille: 200,
            subscriber_count: 1,
        }
    }

    /// A long, widely-shared action with warm remote inputs.
    fn long_shared_warm() -> BreakEvenInputs {
        BreakEvenInputs {
            local_queue_ms: 2_000, // local box is busy
            local_exec_ms: 90_000, // a big LTO link
            remote_queue_ms: 100,
            remote_exec_ms: 45_000, // beefier worker
            input_bytes: 500 << 20,
            inputs_already_local_permille: 900, // mostly warm
            path_bytes_per_ms: 100 << 10,
            path_rtt_ms: 20,
            toolchain_materialization_ms: 0, // staged
            output_bytes: 64 << 20,
            reliability_penalty_ms: 50,
            pressure_penalty_ms: 100,
            uncertainty_permille: 100,
            subscriber_count: 4, // widely shared
        }
    }

    #[test]
    fn golden_fixture_tiny_cold_action_runs_locally() {
        // THE R23 acceptance shape, with golden term values.
        let receipt = evaluate_break_even(&tiny_cold());
        assert_eq!(receipt.decision, BreakEvenDecision::ExecuteLocal);
        assert_eq!(receipt.local_completion_ms, 400);
        // Goldens: transfer = (200MiB/100KiBms + 20ms)/1 = 2068;
        // output return = 10 + 20 = 30.
        assert_eq!(receipt.transfer_ms, 2068);
        assert_eq!(receipt.output_return_ms, 30);
        assert_eq!(
            receipt.remote_completion_ms,
            50 + 2068 + 500 + 150 + 30 + 10
        );
    }

    #[test]
    fn golden_fixture_long_shared_action_goes_remote() {
        let receipt = evaluate_break_even(&long_shared_warm());
        assert_eq!(receipt.decision, BreakEvenDecision::ExecuteRemote);
        // Transfer amortizes across 4 subscribers: (50MiB missing /
        // 100KiB-per-ms + 20) / 4 = 133.
        assert_eq!(receipt.transfer_ms, 133);
        assert!(receipt.remote_completion_ms + receipt.margin_ms < receipt.local_completion_ms);
    }

    #[test]
    fn uncertainty_widens_the_margin_toward_local() {
        // The same numbers, but the estimator admits it knows little:
        // a remote win inside the margin flips to local.
        let mut close_call = long_shared_warm();
        close_call.remote_exec_ms = 80_000; // faster, but only just after overheads
        let confident = evaluate_break_even(&close_call);
        assert_eq!(confident.decision, BreakEvenDecision::ExecuteRemote);
        close_call.uncertainty_permille = 900;
        let uncertain = evaluate_break_even(&close_call);
        assert_eq!(
            uncertain.decision,
            BreakEvenDecision::ExecuteLocal,
            "uncertainty must widen the required remote advantage"
        );
        assert!(uncertain.margin_ms > confident.margin_ms);
    }

    #[test]
    fn receipts_carry_every_term_deterministically() {
        // Identical inputs, identical receipts (pure), and the receipt
        // exposes every term the decision used (rch why's numbers).
        let a = evaluate_break_even(&tiny_cold());
        let b = evaluate_break_even(&tiny_cold());
        assert_eq!(a, b);
        let BreakEvenReceipt {
            transfer_ms: _,
            output_return_ms: _,
            remote_completion_ms: _,
            local_completion_ms: _,
            margin_ms: _,
            decision: _,
        } = a;
    }
}
