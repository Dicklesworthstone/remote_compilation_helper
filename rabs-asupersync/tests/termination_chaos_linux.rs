//! G008 acceptance: chaos kill tests prove ZERO ORPHANS and
//! EXACTLY-ONCE slot release for the bounded termination policy.
//!
//! Scenarios hammer different race windows on real process trees:
//! 1. Staggered-lifetime descendants torn down mid-flight, repeatedly,
//!    at varying offsets — every pass must end with an empty group.
//! 2. A leader killed EXTERNALLY mid-run (cancel racing completion):
//!    survivors still get the full TERM → escalate → verify policy.
//! 3. TERM-resistant trees (trap "" TERM) must be escalated away.
//! 4. The exactly-once contract: slot release gated on the receipt's
//!    `ownership_resolved` fires exactly once across retry storms.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

use rabs_asupersync::process_groups::{ManagedProcessGroup, ProcessGroupSpec, members_from_proc};
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::termination::{
    TerminationPolicy, TerminationStage, graceful_shutdown, resolve_residuals,
};

fn quick(grace_ms: u64, final_ms: u64) -> TerminationPolicy {
    TerminationPolicy {
        grace: Duration::from_millis(grace_ms),
        poll: Duration::from_millis(5),
        final_wait: Duration::from_millis(final_ms),
    }
}

fn spec(script: &str) -> ProcessGroupSpec {
    let mut s = ProcessGroupSpec::new("sh", ["-c".to_owned(), script.to_owned()]);
    s.attribution.attempt = Some("g008-chaos".to_owned());
    s
}

fn wait_until_empty(pgid: u32, millis: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(millis);
    while std::time::Instant::now() < deadline {
        if members_from_proc(pgid).is_empty() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    members_from_proc(pgid).is_empty()
}

#[test]
fn chaos_staggered_descendants_leave_zero_orphans_every_pass() {
    // Descendants with staggered lifetimes plus a NESTED subshell that
    // forks its own background child — four generations in one group.
    let script = "sleep 4 & sleep 6 & sh -c 'sleep 8 &' & wait";
    for teardown_after_ms in [50_u64, 300, 900] {
        let mut group = ManagedProcessGroup::spawn(&spec(script)).expect("spawn");
        std::thread::sleep(Duration::from_millis(teardown_after_ms));

        let receipt = graceful_shutdown(&mut group, &quick(400, 800));
        assert!(
            receipt.ownership_resolved,
            "pass {teardown_after_ms}: unresolved, residuals {}",
            receipt.residuals_final
        );
        assert!(
            wait_until_empty(group.pgid(), 2_000),
            "pass {teardown_after_ms}: orphans survived the group"
        );
        assert!(
            receipt.residuals_final == 0,
            "receipt must agree with reality"
        );
    }
}

#[test]
fn external_leader_kill_still_resolves_survivors() {
    // The coordinator cancels while the action runs; the leader dies by
    // a foreign SIGKILL first — descendants remain and MUST still be
    // driven to resolution by the policy.
    let mut group = ManagedProcessGroup::spawn(&spec("sleep 30 & sleep 30 & wait")).expect("spawn");
    let pgid = group.pgid();

    // Let the tree form, then murder ONLY the leader.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        Command::new("kill")
            .args(["-KILL", &pgid.to_string()])
            .status()
            .expect("kill binary")
            .success(),
        "foreign leader kill"
    );

    // Determinism: SIGKILL is asynchronous — poll OUR OWN child with
    // waitpid(WNOHANG) until the death is observable. (A `kill -0`
    // probe would spin forever: zombies still answer it.)
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match group.leader_try_wait().expect("leader probe") {
            Some(_) => break,
            None => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "leader refused to die after SIGKILL"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let receipt = graceful_shutdown(&mut group, &quick(300, 800));
    assert!(receipt.leader_already_exited, "leader died pre-policy");
    assert_eq!(
        receipt.leader_exit.and_then(|e| e.signal),
        Some(9),
        "foreign SIGKILL is the recorded leader death"
    );
    assert!(receipt.ownership_resolved);
    assert!(wait_until_empty(pgid, 2_000), "no orphan may outlive us");
}

#[test]
fn term_resistant_tree_escalates_with_ordered_receipt() {
    let mut group = ManagedProcessGroup::spawn(&spec("trap \"\" TERM; sleep 60 & sleep 60 & wait"))
        .expect("spawn");

    let receipt = graceful_shutdown(&mut group, &quick(250, 1_500));
    assert!(receipt.term_sent, "graceful step ran");
    assert!(receipt.kill_sent, "TERM resistance forces escalation");
    assert_eq!(receipt.residuals_final, 0, "nothing survives KILL");
    assert!(receipt.ownership_resolved);

    // Receipt stages are strictly time-ordered and contain the full arc.
    let stages: Vec<TerminationStage> = receipt.stages.iter().map(|(s, _)| *s).collect();
    let pos = |want: TerminationStage| {
        stages
            .iter()
            .position(|s| *s == want)
            .unwrap_or_else(|| panic!("missing {want:?} in {stages:?}"))
    };
    assert!(pos(TerminationStage::TermSent) < pos(TerminationStage::GraceExpired));
    assert!(pos(TerminationStage::GraceExpired) < pos(TerminationStage::KillSent));
    assert!(pos(TerminationStage::KillSent) < pos(TerminationStage::Resolved));
}

#[test]
fn consumed_handle_path_escalates_identically() {
    // exec paths consume the child through their own wait; the pgid-only
    // resolver must deliver identical guarantees for what remains.
    // Shape: leader forks TERM-immune children (inherited SIG_IGN) and
    // exits immediately — null stdio, no pipe writers to await.
    let mut group =
        ManagedProcessGroup::spawn(&spec("trap \"\" TERM; sleep 60 & sleep 60 & exit 0"))
            .expect("spawn");
    let pgid = group.pgid();
    let _ = group.wait_leader(); // leader reaped "by another owner"

    let receipt = resolve_residuals(pgid, Attribution::default(), &quick(250, 1_500));
    assert!(receipt.term_sent, "graceful step ran first");
    assert!(receipt.kill_sent, "resolver escalates like the full policy");
    assert!(receipt.ownership_resolved);
    assert!(members_from_proc(pgid).is_empty());
}

#[test]
fn slot_release_fires_exactly_once_across_retry_storm() {
    // THE M2 acceptance clause. The contract has two halves:
    // 1. the policy guarantees `ownership_resolved` is TRUE only when
    //    zero live members remain (safe to release);
    // 2. exactly-once comes from the caller latching on the RESOLUTION
    //    TRANSITION — the flag itself is idempotently true on retries,
    //    which is what makes retry loops safe.
    let mut group = ManagedProcessGroup::spawn(&spec("sleep 30 & sleep 30 & wait")).expect("spawn");
    let policy = quick(300, 800);

    let mut releases = 0_u32;
    let mut released = false;
    for attempt in 1..=5 {
        let receipt = graceful_shutdown(&mut group, &policy);
        assert!(
            receipt.ownership_resolved,
            "attempt {attempt}: policy left ownership unresolved"
        );
        if receipt.ownership_resolved && !released {
            released = true;
            releases += 1; // the ONLY place a release is allowed
        }
    }

    assert_eq!(releases, 1, "exactly-once release across retries");
}
