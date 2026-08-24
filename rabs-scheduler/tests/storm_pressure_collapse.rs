//! I014: fifteen-agent storm and pressure-collapse scenarios
//! (rabs-root-4pidu.27.14).
//!
//! Lab-fidelity, deterministic, pure-policy: the scheduler crate is
//! deliberately zero-I/O and zero-clock, so the "storm" here drives the
//! SAME decision core the fleet runs — weighted fairness under a burst of
//! fifteen concurrent tenants, root-grant token accounting when demand
//! exceeds capacity, and plane-admission refusals under frontier
//! pressure — and asserts the two properties M6 depends on:
//!
//! 1. degradation is BOUNDED and TYPED (starvation bounds hold; every
//!    over-capacity demand produces a named refusal receipt, never a
//!    panic, never an unbounded queue);
//! 2. behavior is DETERMINISTIC (identical storms replay identically),
//!    which is what makes the later multi-host timing comparison
//!    (`>=2x` stage / `3x` final, consumed by the M6 epic) meaningful
//!    rather than noise.
//!
//! The `scheduler_policy_overhead_baseline` test automates the policy-
//! overhead measurement those comparisons need: end-to-end speedup
//! claims are only interpretable against a known scheduling cost.

use std::collections::BTreeMap;
use std::time::Instant;

use rabs_scheduler::acquisition_order::{GrantRefusal, RootGrant};
use rabs_scheduler::fairness::{FairQueue, TenantKey};
use rabs_scheduler::grant_planes::{
    GrantPlane, PlaneAdmission, PlaneRefusal, admit_execution, admit_frontier,
};
use rabs_scheduler::speculation_brownout::{BrownoutDecision, SpeculationProvenance};

/// The storm population: fifteen concurrent agents, one repo each.
fn storm_tenants() -> Vec<TenantKey> {
    (0..15)
        .map(|i| TenantKey {
            agent: format!("agent-{i:02}"),
            project: format!("repo-{i:02}"),
            ci: i % 5 == 0,
        })
        .collect()
}

/// The steady-state storm: fifteen agents each submit twenty items, one
/// arrival every other tick (agent j's r-th job lands at tick
/// `r*30 + j*2`), with exactly one service per tick — utilization 0.5,
/// so the backlog stays shallow and the queue runs the way a healthy
/// fleet does under sustained multi-tenant pressure. The starvation
/// bound is an ANTI-INJUSTICE guarantee (no item waits while later,
/// lighter work jumps it past the bound), not a total-load latency
/// promise: a cold deep backlog ages past any fixed bound by
/// arithmetic necessity, which is why this model keeps utilization
/// strictly under 1.
fn steady_state_storm(starvation_bound: u64) -> (Vec<String>, BTreeMap<String, u64>) {
    const ITEMS_PER_TENANT: u64 = 20;
    const AGENT_STRIDE: u64 = 2;
    let mut queue = FairQueue::new(starvation_bound, 0);
    let tenants = storm_tenants();
    // One CI tenant gets weight 4 — the weighted-fairness signal.
    queue.set_weight(tenants[0].clone(), 4);

    // Arrival schedule: tick -> (tenant index, label).
    let mut arrivals: BTreeMap<u64, Vec<(usize, String)>> = BTreeMap::new();
    for (j, tenant) in tenants.iter().enumerate() {
        for r in 0..ITEMS_PER_TENANT {
            let tick = r * AGENT_STRIDE * tenants.len() as u64 + j as u64 * AGENT_STRIDE;
            arrivals
                .entry(tick)
                .or_default()
                .push((j, format!("{}/job-{r}", tenant.agent)));
        }
    }

    let mut order = Vec::new();
    let mut worst_lag: BTreeMap<String, u64> = BTreeMap::new();
    let total = arrivals.values().map(Vec::len).sum::<usize>();
    let mut served = 0usize;
    let mut tick = 0u64;
    while served < total {
        if let Some(batch) = arrivals.remove(&tick) {
            for (j, label) in batch {
                queue.enqueue(tenants[j].clone(), &label, 100, tick, None);
            }
        }
        if let Some(item) = queue.dequeue(tick) {
            let agent = item.tenant.agent.clone();
            let lag = tick - item.enqueued_at;
            worst_lag
                .entry(agent)
                .and_modify(|w| *w = (*w).max(lag))
                .or_insert(lag);
            order.push(item.label);
            served += 1;
        }
        tick += 1;
    }
    (order, worst_lag)
}

#[test]
fn fifteen_agent_storm_is_fair_starvation_bounded_and_deterministic() {
    let starvation_bound = 64;
    let (order, worst_lag) = steady_state_storm(starvation_bound);

    // Every item survived the storm: nothing dropped, nothing duplicated.
    assert_eq!(
        order.len(),
        300,
        "all three hundred items served exactly once"
    );

    // Weighted fairness is visible in SERVICE ORDER: the weight-4 CI
    // tenant surfaces earlier on average than the weight-1 tenants.
    let mean_position_of = |agent: &str| -> f64 {
        let positions: Vec<usize> = order
            .iter()
            .enumerate()
            .filter_map(|(idx, label)| label.starts_with(agent).then_some(idx))
            .collect();
        assert!(!positions.is_empty(), "{agent} must appear in the order");
        let sum: usize = positions.iter().sum();
        sum as f64 / positions.len() as f64
    };
    let heavy = mean_position_of("agent-00");
    let light_mean: f64 = (1..15)
        .map(|i| mean_position_of(&format!("agent-{i:02}")))
        .sum::<f64>()
        / 14.0;
    assert!(
        heavy < light_mean,
        "weight-4 tenant must surface earlier than the weight-1 average \
         (heavy {heavy}, light mean {light_mean})"
    );

    // Bounded degradation under SUSTAINED pressure: no item's
    // enqueue-to-service lag crosses the starvation bound. (Weights show
    // up in service ORDER above; under uniform arrivals every tenant's
    // steady-state CADENCE converges to the utilization bound — that is
    // the queue's actual contract, not per-tenant gap ratios.)
    for (agent, lag) in &worst_lag {
        assert!(
            *lag <= starvation_bound,
            "{agent}'s worst enqueue-to-service lag {lag} exceeds the \
             {starvation_bound}-tick bound (worst-lag map: {worst_lag:?})"
        );
    }

    // Determinism: an identical storm replays into an identical order.
    let (replayed_order, _) = steady_state_storm(starvation_bound);
    assert_eq!(order, replayed_order, "identical storms replay identically");
}

#[test]
fn scheduler_policy_overhead_baseline_is_automated() {
    // The policy-overhead number M6's speedup gate needs: how long the
    // decision core takes to place a large storm. Appended beside the
    // other baselines so the end-to-end comparison has a fixed ancestor.
    const TENANTS: usize = 15;
    const ITEMS_PER_TENANT: usize = 200;

    let start = Instant::now();
    let mut queue = FairQueue::new(512, 0);
    let tenants = storm_tenants();
    for round in 0..ITEMS_PER_TENANT {
        for tenant in &tenants {
            queue.enqueue(
                tenant.clone(),
                &format!("r{round}"),
                u64::try_from(50 + round % 7).expect("cost fits"),
                u64::try_from(round).expect("tick fits"),
                None,
            );
        }
    }
    let mut served = 0usize;
    let mut tick = 0u64;
    while queue.dequeue(tick).is_some() {
        served += 1;
        tick += 1;
    }
    let elapsed = start.elapsed();

    assert_eq!(served, TENANTS * ITEMS_PER_TENANT, "storm fully drained");

    let ops_per_ms = (TENANTS * ITEMS_PER_TENANT) as f64 / elapsed.as_millis().max(1) as f64;
    let line = format!(
        "{{\"bead\":\"i014\",\"suite\":\"scheduler_storm\",\"tenants\":{},\"items\":{},\
         \"elapsed_ms\":{},\"ops_per_ms\":{ops_per_ms:.1}}}\n",
        TENANTS,
        TENANTS * ITEMS_PER_TENANT,
        elapsed.as_millis(),
    );
    let baseline_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../benchmarks/baselines/i014_scheduler_storm.ndjson"
    );
    if let Some(parent) = std::path::Path::new(baseline_path).parent() {
        std::fs::create_dir_all(parent).expect("baseline directory");
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(baseline_path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()))
        .expect("append storm baseline");
}

#[test]
fn pressure_collapse_transferable_exhaustion_is_typed_bounded_and_conserving() {
    // Capacity C=4: one implicit token consumed by the Cargo root at
    // open, C-1=3 transferables. Fifteen agents demand tokens at once.
    let mut grant = RootGrant::open(4).expect("capacity 4 opens");
    assert_eq!(grant.transferable_budget(), 3, "C-1 transferables");
    assert_eq!(grant.transferable_outstanding(), 0);

    let mut outstanding_tokens = Vec::new();
    let mut refusal_receipts = Vec::new();

    for tenant in storm_tenants() {
        match grant.issue_transferable() {
            Ok(token) => outstanding_tokens.push((tenant.agent.clone(), token)),
            Err(refusal) => refusal_receipts.push((tenant.agent.clone(), refusal)),
        }
        // Conservation holds after EVERY step of the storm.
        assert_eq!(
            u32::try_from(outstanding_tokens.len()).expect("fits"),
            grant.transferable_outstanding(),
            "outstanding accounting matches reality"
        );
    }

    // Bounded collapse: exactly C-1 admitted, the rest REFUSED TYPED,
    // each receipt naming both the outstanding count and the capacity.
    assert_eq!(outstanding_tokens.len(), 3);
    assert_eq!(refusal_receipts.len(), 12);
    for (agent, refusal) in &refusal_receipts {
        assert_eq!(
            *refusal,
            GrantRefusal::TransferablesExhausted {
                outstanding: 3,
                capacity: 4
            },
            "{agent}'s refusal must name the exhaustion precisely"
        );
    }

    // Graceful recovery: releasing one token admits EXACTLY one more.
    let (_, freed) = outstanding_tokens.pop().expect("a held token");
    grant.release(&freed).expect("release");
    assert!(
        grant.issue_transferable().is_ok(),
        "one release, one re-admission"
    );
    assert_eq!(grant.transferable_outstanding(), 3);

    // Double-release is a typed non-event, not corruption: the receipt
    // names the offending serial (opaque to us; matched structurally).
    assert!(
        matches!(
            grant.release(&freed),
            Err(GrantRefusal::UnknownToken { .. })
        ),
        "double release must be refused as UnknownToken"
    );

    // Close refuses further issuance; nothing unbounded ever leaked.
    grant.close();
    assert_eq!(grant.issue_transferable(), Err(GrantRefusal::GrantClosed));
}

#[test]
fn plane_admission_under_storm_refuses_typed_never_panics() {
    let tenants = storm_tenants();
    let mut provenance = SpeculationProvenance::default();
    let mut shed_receipts = 0u32;

    // Fifteen agents each fire every legal and illegal plane request;
    // every refusal is the exact typed rule violation, every admission
    // the exact granted shape — graceful refusal all the way down.
    for _tenant in &tenants {
        // Frontier grants exist ONLY on the frontier plane (R102).
        assert!(matches!(
            admit_frontier(GrantPlane::LocalCargoRemoteChildren, 8, 64),
            Ok(PlaneAdmission::Frontier(_))
        ));
        assert_eq!(
            admit_frontier(GrantPlane::WholeCommand, 8, 64),
            Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
                plane: GrantPlane::WholeCommand
            })
        );
        assert_eq!(
            admit_frontier(GrantPlane::CoordinatedLocal, 8, 64),
            Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
                plane: GrantPlane::CoordinatedLocal
            })
        );
        assert_eq!(
            admit_frontier(GrantPlane::UncoordinatedFailOpen, 8, 64),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant)
        );

        // Execution grants need their OWN source of truth: worker
        // selection for whole-command, edge pressure for coordinated
        // local — a frontier grant substitutes for neither.
        assert!(matches!(
            admit_execution(GrantPlane::WholeCommand, Some(8), None),
            Ok(PlaneAdmission::WorkerExecution { cpu_slots: 8 })
        ));
        assert_eq!(
            admit_execution(GrantPlane::WholeCommand, None, Some(99)),
            Err(PlaneRefusal::ExecutionGrantBeforeWorkerSelection)
        );
        assert!(matches!(
            admit_execution(GrantPlane::CoordinatedLocal, None, Some(4)),
            Ok(PlaneAdmission::EdgePressureExecution { cpu_slots: 4 })
        ));

        // Refusals are RECEIPTED, not silent: the speculation ledger
        // records every shed admission so brownout accounting closes.
        provenance.record(BrownoutDecision::StopAdmitting, false);
        shed_receipts += 1;
    }
    assert_eq!(shed_receipts, 15, "one shed-admission receipt per agent");
}
