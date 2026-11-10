//! Admission ownership against the public production circuit implementation.

use rch_common::{CircuitBreakerConfig, CircuitStats};

#[test]
fn circuit_selection_permit_releases_abandoned_and_retains_committed_probe() {
    let mut stats = CircuitStats::new();
    let config = CircuitBreakerConfig {
        half_open_max_probes: 1,
        ..Default::default()
    };
    stats.half_open();
    let abandoned = stats.reserve_selection(&config).unwrap();
    assert!(stats.allows_selection(&abandoned));
    assert!(stats.reserve_selection(&config).is_none());
    assert!(!stats.start_probe(&config));
    // Liveness outcomes cannot spend a selection that has not started work.
    stats.record_success();
    assert!(!stats.can_probe(&config));
    drop(abandoned);
    assert!(stats.can_probe(&config));

    stats.reserve_selection(&config).unwrap().commit();
    assert!(!stats.can_probe(&config));
    stats.record_success();
    assert!(stats.can_probe(&config));
    stats.reserve_selection(&config).unwrap().commit();
    stats.record_failure();
    assert!(stats.can_probe(&config));
}

#[test]
fn circuit_selection_permit_shares_probe_budget_with_health_probes() {
    let mut stats = CircuitStats::new();
    let config = CircuitBreakerConfig {
        half_open_max_probes: 2,
        ..Default::default()
    };
    stats.half_open();
    assert!(stats.start_probe(&config));
    let selection = stats.reserve_selection(&config).unwrap();
    assert!(!stats.can_probe(&config));
    assert!(stats.reserve_selection(&config).is_none());
    stats.record_success();
    // The health probe finished; the pending selection still owns one slot.
    assert!(stats.can_probe(&config));
    let second = stats.reserve_selection(&config).unwrap();
    assert!(!stats.can_probe(&config));
    selection.commit();
    stats.record_success();
    assert!(stats.can_probe(&config));
    assert!(stats.allows_selection(&second));
    drop(second);
    assert!(stats.start_probe(&config));
    assert!(stats.start_probe(&config));
    assert!(!stats.start_probe(&config));
}

#[test]
fn circuit_selection_permit_cannot_cross_circuit_generations() {
    let mut stats = CircuitStats::new();
    let config = CircuitBreakerConfig {
        half_open_max_probes: 1,
        ..Default::default()
    };
    let closed = stats.reserve_selection(&config).unwrap();
    stats.open();
    assert!(!stats.allows_selection(&closed));
    assert!(stats.reserve_selection(&config).is_none());
    stats.half_open();
    assert!(!stats.allows_selection(&closed));
    let old = stats.reserve_selection(&config).unwrap();
    stats.open();
    stats.half_open();
    let current = stats.reserve_selection(&config).unwrap();
    assert!(!stats.allows_selection(&old));
    drop(old);
    assert!(!stats.can_probe(&config));
    assert!(stats.allows_selection(&current));
    // Finishing a diagnostic clone must not release authoritative ownership.
    current.commit();
    let mut diagnostic = stats.clone();
    diagnostic.record_success();
    assert!(diagnostic.can_probe(&config));
    assert!(!stats.can_probe(&config));
    stats.record_success();
    assert!(stats.can_probe(&config));
}
