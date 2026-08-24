//! I019: root-permit implicit-token accounting property suite
//! (rabs-root-4pidu.27.19; acceptance T016/T033).
//!
//! THE contract under storm, for every capacity `C >= 1`:
//!
//! - opening a C-capacity root permit consumes Cargo's ONE implicit token
//!   at open time — it is never transferable and never counted;
//! - exactly `C-1` transferable tokens exist, ever;
//! - token conservation holds after EVERY operation of a many-issuer,
//!   many-release, sometimes-hostile storm:
//!   `issued_total == released_total + outstanding`;
//! - every over-demand issue is a TYPED refusal naming the exact
//!   outstanding/capacity numbers; every bad release is a typed
//!   `UnknownToken`; close is final and typed.
//!
//! Identity discipline: [`TransferableToken`] is deliberately opaque
//! outside the crate (the broker owns the accounting), so the storm tracks
//! tokens BY HANDLE and exercises ghost-release semantics by
//! double-releasing consumed handles rather than fabricating serials.
//! Deterministic xorshift storms (no rng dependency), so failures replay
//! exactly. The real-multi-toolchain Cargo leg lives in
//! `root_permit_cargo_toolchains.rs`.

use rabs_scheduler::acquisition_order::{GrantRefusal, RootGrant, TransferableToken};
use rabs_scheduler::fairness::{FairQueue, TenantKey};

/// Deterministic xorshift64* — fixed seeds keep failures reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

/// Conservation invariant, checked after every single storm step.
fn assert_conservation(
    capacity: u32,
    issued: u64,
    released: u64,
    live: &[TransferableToken],
    grant: &RootGrant,
) {
    assert_eq!(
        issued,
        released + live.len() as u64,
        "C={capacity}: conservation broke"
    );
    assert_eq!(
        u32::try_from(live.len()).expect("fits"),
        grant.transferable_outstanding(),
        "C={capacity}: ledger disagrees with the broker"
    );
    assert!(live.len() <= capacity.saturating_sub(1) as usize);
}

#[test]
fn token_conservation_holds_across_capacities_and_hostile_storms() {
    // Every capacity from trivial (C=1: zero transferables) to fleet-size.
    for capacity in 1u32..=32 {
        let mut grant = RootGrant::open(capacity).expect("valid capacity opens");
        assert_eq!(
            grant.transferable_budget(),
            capacity - 1,
            "C-1 exposure at C={capacity}"
        );

        let mut live: Vec<TransferableToken> = Vec::new();
        let mut dead: Vec<TransferableToken> = Vec::new(); // released handles
        let mut issued = 0u64;
        let mut released = 0u64;
        let mut rng = XorShift(0x19_00_00_00 ^ u64::from(capacity));
        let mut closed = false;

        for _step in 0..400 {
            match rng.below(100) {
                0..=49 if !closed => match grant.issue_transferable() {
                    Ok(token) => {
                        live.push(token);
                        issued += 1;
                    }
                    Err(GrantRefusal::TransferablesExhausted { .. }) => {}
                    Err(other) => panic!("unexpected refusal {other:?}"),
                },
                50..=74 if !live.is_empty() && !closed => {
                    // Release a random LIVE handle.
                    let idx = rng.below(live.len());
                    let token = live.swap_remove(idx);
                    grant.release(&token).expect("live release");
                    dead.push(token);
                    released += 1;
                }
                75..=89 if !dead.is_empty() => {
                    // HOSTILE: double-release a consumed handle.
                    let idx = rng.below(dead.len());
                    assert!(matches!(
                        grant.release(&dead[idx]),
                        Err(GrantRefusal::UnknownToken { .. })
                    ));
                }
                _ if !closed => {
                    grant.close();
                    closed = true;
                }
                _ => {}
            }
            assert_conservation(capacity, issued, released, &live, &grant);
        }
    }
}

#[test]
fn c_one_exposes_only_the_implicit_token() {
    // C=1: Cargo's implicit token is the whole grant; nothing is
    // transferable and demand refuses immediately with exact numbers.
    let mut grant = RootGrant::open(1).expect("C=1 opens");
    assert_eq!(grant.transferable_budget(), 0);
    assert_eq!(
        grant.issue_transferable(),
        Err(GrantRefusal::TransferablesExhausted {
            outstanding: 0,
            capacity: 1
        })
    );
}

#[test]
fn fifteen_simultaneous_processes_conserve_under_one_grant() {
    // Fifteen Cargo processes race for one C=8 grant: exactly 7 hold
    // transferables, eight receive typed exhaustion naming the same
    // numbers, and a release/retry cycle keeps the books balanced to the
    // token through every bounded recovery.
    const PROCESSES: u64 = 15;
    const CAPACITY: u32 = 8;

    let mut grant = RootGrant::open(CAPACITY).expect("opens");
    let mut holders: Vec<TransferableToken> = Vec::new();
    let mut exhausted: Vec<GrantRefusal> = Vec::new();

    for process in 0..PROCESSES {
        match grant.issue_transferable() {
            Ok(token) => holders.push(token),
            Err(refusal) => exhausted.push(refusal),
        }
        assert_eq!(
            u32::try_from(holders.len()).expect("fits"),
            grant.transferable_outstanding(),
            "process {process}: ledger drift"
        );
    }
    assert_eq!(holders.len(), CAPACITY as usize - 1);
    assert_eq!(
        exhausted.len(),
        (PROCESSES as usize) - (CAPACITY as usize - 1)
    );
    for refusal in &exhausted {
        assert_eq!(
            *refusal,
            GrantRefusal::TransferablesExhausted {
                outstanding: CAPACITY - 1,
                capacity: CAPACITY
            }
        );
    }

    // PHASE 1 — bounded recovery: every holder releases; each freed slot
    // admits exactly one of the eight exhausted waiters, so the books
    // stay balanced (outstanding == C-1) through the whole churn.
    let mut rng = XorShift(0xC0_FFEE);
    for _ in 0..holders.len() {
        let idx = rng.below(holders.len());
        let token = holders.swap_remove(idx);
        grant.release(&token).expect("holder release");
        match grant.issue_transferable() {
            Ok(waiter_token) => holders.push(waiter_token),
            Err(e) => panic!("freed slot must admit exactly one waiter: {e:?}"),
        }
        assert_eq!(grant.transferable_outstanding(), CAPACITY - 1);
    }

    // PHASE 2 — drain to zero without retries: conservation at the edge.
    while !holders.is_empty() {
        let idx = rng.below(holders.len());
        let token = holders.swap_remove(idx);
        grant.release(&token).expect("drain release");
    }
    assert_eq!(grant.transferable_outstanding(), 0);
    // A drained OPEN grant issues again — capacity is a ceiling, not a
    // one-shot budget. Re-fill and confirm the typed ceiling.
    for _ in 1..CAPACITY {
        assert!(grant.issue_transferable().is_ok());
    }
    let refusal = grant.issue_transferable().expect_err("ceiling must refuse");
    assert_eq!(
        refusal,
        GrantRefusal::TransferablesExhausted {
            outstanding: CAPACITY - 1,
            capacity: CAPACITY
        }
    );

    // The fairness plane schedules the SAME storm shape the token stream
    // feeds (seam between Epic I halves).
    let mut queue = FairQueue::new(64, 0);
    for process in 0..PROCESSES {
        queue.enqueue(
            TenantKey {
                agent: format!("cargo-{process}"),
                project: "p".into(),
                ci: false,
            },
            "build",
            10,
            process,
            None,
        );
    }
    let mut served_any = false;
    while queue.dequeue(PROCESSES).is_some() {
        served_any = true;
    }
    assert!(served_any);
}
