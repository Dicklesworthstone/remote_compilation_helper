//! Real socket exercises of the production decision loop, not a second retry
//! implementation. Peer frames are fixtures: no real compiler execution,
//! daemon admission, or cache qualification is claimed by these tests.
use super::*;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const CAPACITY: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\"reason\":\"edge-capacity\",\"retry\":\"decision-capacity-v1\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const WAIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"wait\",\"action_key\":\"key\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const PREPARING: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"preparing\",\"reason\":\"toolchain-facts-pending\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const EXECUTE: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"execute\",\"action_key\":\"key\",\"capture_protocol\":1,\"attempt\":\"admitted\",\"env\":[]}\n";
const HIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"action_key\":\"key\",\"capture_protocol\":1,\"compiler_skip_authorized\":false}\n";

fn policy(retries: u32) -> WaitPolicy {
    WaitPolicy {
        budget: Duration::from_secs(2),
        preparation_budget: Duration::from_secs(2),
        retries,
        initial_delay: Duration::ZERO,
        maximum_delay: Duration::ZERO,
        preparation_maximum_delay: Duration::ZERO,
    }
}

fn reader(stream: UnixStream) -> BufReader<ConsultStream> {
    BufReader::new(ConsultStream {
        stream,
        deadline: Instant::now() + Duration::from_secs(2),
    })
}

fn exchange(replies: &[String], settings: WaitPolicy) -> (Result<Live, ()>, Vec<String>) {
    let replies = replies.to_vec();
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        let mut requests = Vec::new();
        let last = replies.len() - 1;
        for (index, reply) in replies.into_iter().enumerate() {
            peer.get_mut().write_all(reply.as_bytes()).unwrap();
            if index != last {
                let mut line = String::new();
                if peer.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                requests.push(line);
            }
        }
        requests
    });
    let outcome = read_with_policy(
        reader(stream),
        "unchanged request",
        Duration::from_secs(1),
        true,
        settings,
        None,
        &|| true,
    );
    (outcome, daemon.join().unwrap())
}

#[test]
fn capacity_waits_cross_readiness_and_keyed_flights_without_starting_work() {
    let (result, requests) = exchange(
        &[
            CAPACITY.into(),
            PREPARING.into(),
            WAIT.into(),
            CAPACITY.into(),
            EXECUTE.into(),
        ],
        policy(8),
    );
    assert!(matches!(result, Ok(Live::Execute { attempt, env, .. })
        if attempt == "admitted" && env.is_empty()));
    assert_eq!(requests, vec!["unchanged request\n"; 4]);
}

#[test]
fn capacity_never_erases_a_key_or_authorizes_a_different_action() {
    for last in [
        PREPARING.to_owned(),
        WAIT.replace("\"key\"", "\"different\""),
        EXECUTE.replace("\"key\"", "\"different\""),
        HIT.replace("\"key\"", "\"different\""),
        EXECUTE.replace("\"action_key\":\"key\",", ""),
    ] {
        let (result, requests) = exchange(&[WAIT.into(), CAPACITY.into(), last], policy(8));
        assert!(result.is_err());
        assert_eq!(requests, vec!["unchanged request\n"; 2]);
    }
}

#[test]
fn all_wait_reasons_spend_one_retry_quota() {
    let (result, requests) = exchange(
        &[
            CAPACITY.into(),
            PREPARING.into(),
            WAIT.into(),
            CAPACITY.into(),
        ],
        policy(3),
    );
    assert!(matches!(result, Ok(Live::PassThrough)));
    assert_eq!(requests, vec!["unchanged request\n"; 3]);
}

#[test]
fn legacy_capacity_and_other_passthrough_decisions_are_not_retried() {
    for frame in [
        "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\"reason\":\"edge-capacity\"}\n",
        "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\"reason\":\"edge-work-failed\"}\n",
    ] {
        let (result, requests) = exchange(&[frame.into(), EXECUTE.into()], policy(8));
        assert!(matches!(result, Ok(Live::PassThrough)));
        assert!(requests.is_empty());
    }
}

#[test]
fn disabled_waiting_keeps_legacy_passthrough_and_emits_no_request() {
    for may_wait in [false, true] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.write_all(CAPACITY.as_bytes()).unwrap();
        let mut settings = policy(8);
        if may_wait {
            settings.preparation_budget = Duration::ZERO;
        }
        let result = read_with_policy(
            reader(stream),
            "must not retry",
            Duration::from_secs(1),
            may_wait,
            settings,
            None,
            &|| true,
        );
        assert!(matches!(result, Ok(Live::PassThrough)));
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
}

#[test]
fn capacity_hints_require_unambiguous_version_and_nonownership() {
    assert_eq!(
        wait_for(&reply_json::parse(CAPACITY).unwrap()),
        Some(WaitFor::Capacity)
    );
    for frame in [
        CAPACITY.replace("decision-capacity-v1", "decision-capacity-v2"),
        CAPACITY.replace("edge-capacity", "store-busy"),
        CAPACITY.replace(
            "\"compiler_skip_authorized\":false",
            "\"compiler_skip_authorized\":true",
        ),
        CAPACITY.replace(
            "\"materialization_started\":false",
            "\"materialization_started\":true",
        ),
        CAPACITY.replace(
            "\"materialization_started\":false",
            "\"materialization_started\":null",
        ),
        CAPACITY.replace(
            "\"materialization_started\":false",
            "\"materialization_started\":false,\"materialization_started\":false",
        ),
        CAPACITY.replace(
            "\"retry\":",
            "\"retry\":\"decision-capacity-v1\",\"retry\":",
        ),
        CAPACITY.replace("\"retry\":", "\"action_key\":null,\"retry\":"),
        CAPACITY.replace("\"retry\":", "\"attempt\":null,\"attempt\":null,\"retry\":"),
        CAPACITY.replace("\"retry\":", "\"env\":[],\"retry\":"),
    ] {
        assert!(
            wait_for(&reply_json::parse(&frame).unwrap()).is_none(),
            "{frame}"
        );
        let (result, requests) = exchange(&[frame, EXECUTE.into()], policy(8));
        assert!(result.is_err());
        assert!(requests.is_empty());
    }
}

#[test]
fn capacity_does_not_renew_the_absolute_wait_deadline() {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        for reply in [WAIT, CAPACITY] {
            peer.get_mut().write_all(reply.as_bytes()).unwrap();
            let mut line = String::new();
            assert!(peer.read_line(&mut line).unwrap() > 0);
            assert_eq!(line, "unchanged request\n");
        }
        for _ in 0..300 {
            if peer.get_mut().write_all(b" ").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("capacity reply renewed the wait deadline");
    });
    let mut settings = policy(8);
    settings.budget = Duration::from_millis(150);
    settings.preparation_budget = Duration::from_secs(30);
    let result = read_with_policy(
        reader(stream),
        "unchanged request",
        Duration::from_secs(30),
        true,
        settings,
        None,
        &|| true,
    );
    assert!(result.is_err());
    daemon.join().unwrap();
}

#[test]
fn caller_loss_during_capacity_backoff_is_not_local_fallback_permission() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.write_all(CAPACITY.as_bytes()).unwrap();
    let owned = Arc::new(AtomicBool::new(true));
    let revoked = Arc::clone(&owned);
    let daemon = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        revoked.store(false, Ordering::Release);
        let mut bytes = Vec::new();
        let result = peer.read_to_end(&mut bytes);
        assert!(
            result.is_ok()
                || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
        );
        assert!(bytes.is_empty());
    });
    let mut settings = policy(8);
    settings.preparation_budget = Duration::from_secs(30);
    settings.initial_delay = Duration::from_secs(10);
    settings.preparation_maximum_delay = Duration::from_secs(10);
    let result = read_with_policy(
        reader(stream),
        "must not retry",
        Duration::from_secs(30),
        true,
        settings,
        None,
        &|| owned.load(Ordering::Acquire),
    );
    assert!(result.is_err());
    daemon.join().unwrap();
}

#[test]
fn capacity_after_hit_acceptance_is_uncertain_delivery_not_retry_or_fallback() {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        peer.get_mut().write_all(CAPACITY.as_bytes()).unwrap();
        let mut line = String::new();
        peer.read_line(&mut line).unwrap();
        assert_eq!(line, "unchanged request\n");
        peer.get_mut().write_all(HIT.as_bytes()).unwrap();
        line.clear();
        peer.read_line(&mut line).unwrap();
        assert_eq!(line, "{\"kind\":\"rustc-accept\"}\n");
        peer.get_mut().write_all(CAPACITY.as_bytes()).unwrap();
        line.clear();
        assert_eq!(peer.read_line(&mut line).unwrap(), 0);
    });
    let result = read_with_policy(
        reader(stream),
        "unchanged request",
        Duration::from_secs(1),
        true,
        policy(8),
        None,
        &|| true,
    );
    assert!(matches!(result, Ok(Live::FailClosed(_))));
    daemon.join().unwrap();
}
