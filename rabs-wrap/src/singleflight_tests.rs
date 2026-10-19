use super::policy::MAX_RETRIES;
use super::*;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const WAIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"wait\",\"action_key\":\"key\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const PREPARING: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"preparing\",\"reason\":\"toolchain-facts-pending\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const EXECUTE: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"execute\",\"action_key\":\"key\",\"capture_protocol\":1,\"attempt\":\"admitted\",\"env\":[]}\n";

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

fn exchange(replies: Vec<String>, settings: WaitPolicy) -> (Result<Live, ()>, Vec<String>) {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
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
    let result = read_with_policy(
        reader(stream),
        "original bytes",
        Duration::from_secs(1),
        true,
        settings,
        None,
        &|| true,
    );
    (result, daemon.join().unwrap())
}

#[test]
fn cold_facts_join_a_keyed_flight_then_one_admitted_execution() {
    let (result, requests) = exchange(
        vec![
            PREPARING.to_owned(),
            PREPARING.replace("toolchain-facts-pending", "package-facts-pending"),
            PREPARING.replace("toolchain-facts-pending", "dependency-facts-pending"),
            WAIT.to_owned(),
            EXECUTE.to_owned(),
        ],
        policy(8),
    );
    match result {
        Ok(Live::Execute { attempt, env, .. }) => {
            assert_eq!(attempt, "admitted");
            assert!(env.is_empty());
        }
        _ => panic!("only the final keyed decision may admit execution"),
    }
    assert_eq!(requests, vec!["original bytes\n"; 4]);
}

#[test]
fn preparation_can_finish_without_a_singleflight_wait() {
    let (result, requests) = exchange(vec![PREPARING.to_owned(), EXECUTE.to_owned()], policy(3));
    assert!(matches!(result, Ok(Live::Execute { .. })));
    assert_eq!(requests, ["original bytes\n"]);
}

#[test]
fn preparation_and_keyed_waiting_share_one_retry_quota() {
    let (result, requests) = exchange(
        vec![
            PREPARING.to_owned(),
            PREPARING.replace("toolchain-facts-pending", "package-facts-pending"),
            WAIT.to_owned(),
        ],
        policy(2),
    );
    assert!(matches!(result, Ok(Live::PassThrough)));
    assert_eq!(requests, vec!["original bytes\n"; 2]);
}

#[test]
fn preparation_cannot_erase_or_change_a_bound_action_key() {
    for final_reply in [
        PREPARING.to_owned(),
        WAIT.replace("\"key\"", "\"different\""),
        EXECUTE.replace("\"key\"", "\"different\""),
    ] {
        let (result, requests) = exchange(
            vec![PREPARING.to_owned(), WAIT.to_owned(), final_reply],
            policy(8),
        );
        assert!(result.is_err());
        assert_eq!(requests, vec!["original bytes\n"; 2]);
    }
}

#[test]
fn preparation_requires_a_real_unambiguous_key_before_execution() {
    for final_reply in [
        EXECUTE.replace("\"action_key\":\"key\",", ""),
        EXECUTE.replace("\"action_key\":\"key\"", "\"action_key\":\"\""),
        EXECUTE.replace(
            "\"action_key\":\"key\"",
            "\"action_key\":\"key\",\"action_key\":\"key\"",
        ),
    ] {
        let (result, requests) = exchange(vec![PREPARING.to_owned(), final_reply], policy(3));
        assert!(result.is_err());
        assert_eq!(requests, ["original bytes\n"]);
    }
}

#[test]
fn a_remote_offer_cannot_change_the_action_key_followed_by_this_waiter() {
    for changed in [
        "\"action_key\":\"different\"",
        "\"action_key\":\"\"",
        "\"action_key\":\"key\",\"action_key\":\"key\"",
    ] {
        let (stream, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let offer = format!(
            "{{\"kind\":\"rustc-decision\",\"decision\":\"remote\",{changed},\"remote_protocol\":1,\"capture_protocol\":1,\"compiler_skip_authorized\":false}}\n"
        );
        let daemon = std::thread::spawn(move || {
            let mut peer = BufReader::new(peer);
            peer.get_mut().write_all(WAIT.as_bytes()).unwrap();
            let mut retry = String::new();
            peer.read_line(&mut retry).unwrap();
            assert_eq!(retry, "original bytes\n");
            peer.get_mut().write_all(offer.as_bytes()).unwrap();
            let mut consent = String::new();
            peer.read_line(&mut consent).unwrap();
            consent
        });
        let outcome = read_with_policy(
            reader(stream),
            "original bytes",
            Duration::from_secs(1),
            true,
            policy(3),
            None,
            &|| true,
        );
        assert!(outcome.is_err(), "a foreign remote offer is not our flight");
        assert!(
            daemon.join().unwrap().is_empty(),
            "the changed action must receive no private-execution ACK"
        );
    }
}

#[test]
fn preparation_frames_never_smuggle_authority_or_unknown_stages() {
    for bad in [
        PREPARING.replace(
            "\"compiler_skip_authorized\":false",
            "\"compiler_skip_authorized\":true",
        ),
        PREPARING.replace(
            "\"materialization_started\":false",
            "\"materialization_started\":true",
        ),
        PREPARING.replace(
            "\"materialization_started\":false",
            "\"materialization_started\":false,\"materialization_started\":false",
        ),
        PREPARING.replace(
            "\"reason\":",
            "\"attempt\":null,\"attempt\":null,\"reason\":",
        ),
        PREPARING.replace("\"reason\":", "\"env\":[],\"reason\":"),
        PREPARING.replace("\"reason\":", "\"action_key\":null,\"reason\":"),
        PREPARING.replace(
            "\"reason\":",
            "\"reason\":\"toolchain-facts-pending\",\"reason\":",
        ),
        PREPARING.replace("toolchain-facts-pending", "unknown-stage"),
    ] {
        assert!(
            wait_for(&reply_json::parse(&bad).unwrap()).is_none(),
            "{bad}"
        );
    }
    assert_eq!(
        wait_for(&reply_json::parse(PREPARING).unwrap()),
        Some(WaitFor::Facts)
    );
}

#[test]
fn a_prepared_hit_still_requires_acceptance_and_completed_installation() {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        peer.get_mut().write_all(PREPARING.as_bytes()).unwrap();
        let mut line = String::new();
        peer.read_line(&mut line).unwrap();
        assert_eq!(line, "original bytes\n");
        peer.get_mut()
            .write_all(
                b"{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"action_key\":\"key\",\"capture_protocol\":1,\"compiler_skip_authorized\":false}\n",
            )
            .unwrap();
        line.clear();
        peer.read_line(&mut line).unwrap();
        assert_eq!(line, "{\"kind\":\"rustc-accept\"}\n");
        peer.get_mut()
            .write_all(
                b"{\"kind\":\"rustc-decision\",\"decision\":\"served\",\"compiler_skip_authorized\":true,\"stderr_hex\":\"6869\"}\n",
            )
            .unwrap();
    });
    let result = read_with_policy(
        reader(stream),
        "original bytes",
        Duration::from_secs(1),
        true,
        policy(3),
        None,
        &|| true,
    );
    assert!(matches!(result, Ok(Live::Served(bytes)) if bytes == b"hi"));
    daemon.join().unwrap();
}

#[test]
fn preparation_budget_zero_and_unnegotiated_preparation_never_retry() {
    for negotiated in [true, false] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(PREPARING.as_bytes()).unwrap();
        let mut settings = policy(3);
        settings.budget = Duration::ZERO;
        settings.preparation_budget = Duration::ZERO;
        let result = read_with_policy(
            reader(stream),
            "original bytes",
            Duration::from_secs(1),
            negotiated,
            settings,
            None,
            &|| true,
        );
        if negotiated {
            assert!(matches!(result, Ok(Live::PassThrough)));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
}

#[test]
fn retry_count_bounds_even_a_peer_that_answers_immediately() {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        let mut requests = 0;
        loop {
            peer.get_mut().write_all(WAIT.as_bytes()).unwrap();
            let mut line = String::new();
            if peer.read_line(&mut line).unwrap() == 0 {
                break;
            }
            assert_eq!(line, "original bytes\n");
            requests += 1;
        }
        requests
    });
    assert!(matches!(
        read_with_policy(
            reader(stream),
            "original bytes",
            Duration::from_secs(1),
            true,
            policy(3),
            None,
            &|| true,
        ),
        Ok(Live::PassThrough)
    ));
    assert_eq!(daemon.join().unwrap(), 3);
    const {
        assert!(
            MAX_RETRIES + 1 < 64,
            "leave room below the edge request quota"
        );
    }
}

#[test]
fn zero_wait_budget_never_sends_a_retry_or_acceptance() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(WAIT.as_bytes()).unwrap();
    let mut settings = policy(3);
    settings.budget = Duration::ZERO;
    assert!(matches!(
        read_with_policy(
            reader(stream),
            "original",
            Duration::from_secs(1),
            true,
            settings,
            None,
            &|| true,
        ),
        Ok(Live::PassThrough)
    ));
    assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn malformed_authority_or_unnegotiated_waits_are_not_followed() {
    for (line, negotiated) in [
        (WAIT.to_owned(), false),
        (
            WAIT.replace(
                "\"compiler_skip_authorized\":false",
                "\"compiler_skip_authorized\":true",
            ),
            true,
        ),
        (
            WAIT.replace(
                "\"materialization_started\":false",
                "\"materialization_started\":true",
            ),
            true,
        ),
        (
            WAIT.replace("\"action_key\":\"key\"", "\"action_key\":\"\""),
            true,
        ),
        (
            WAIT.replace(
                "\"action_key\":\"key\"",
                "\"action_key\":\"key\",\"action_key\":\"other\"",
            ),
            true,
        ),
        (
            WAIT.replace(
                "\"materialization_started\":false",
                "\"attempt\":\"admitted\"",
            ),
            true,
        ),
        (
            WAIT.replace(
                "\"action_key\":\"key\"",
                "\"action_key\":\"key\",\"attempt\":null,\"attempt\":null",
            ),
            true,
        ),
        (
            WAIT.replace(
                "\"action_key\":\"key\"",
                "\"action_key\":\"key\",\"env\":[],\"env\":[]",
            ),
            true,
        ),
    ] {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(line.as_bytes()).unwrap();
        assert!(
            read_with_policy(
                reader(stream),
                "original",
                Duration::from_secs(1),
                negotiated,
                policy(3),
                None,
                &|| true,
            )
            .is_err()
        );
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
}

#[test]
fn trickling_peer_cannot_hold_a_follower_past_its_wait_budget() {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let daemon = std::thread::spawn(move || {
        let mut peer = BufReader::new(peer);
        peer.get_mut().write_all(WAIT.as_bytes()).unwrap();
        let mut line = String::new();
        assert!(peer.read_line(&mut line).unwrap() > 0);
        for _ in 0..300 {
            if peer.get_mut().write_all(b" ").is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });
    let mut settings = policy(60);
    settings.budget = Duration::from_millis(100);
    let outcome = read_with_policy(
        reader(stream),
        "original",
        Duration::from_secs(10),
        true,
        settings,
        None,
        &|| true,
    );
    assert!(outcome.is_err());
    assert!(
        daemon.join().unwrap(),
        "follower must close before the trickle ends"
    );
}

#[test]
fn caller_loss_interrupts_partial_decision_without_accepting_or_retrying() {
    let owned = Arc::new(AtomicBool::new(true));
    let revoked = Arc::clone(&owned);
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.write_all(b"{\"kind\":\"rustc-decision\",\"decision\":\"hit\"")
        .unwrap();
    let daemon = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        revoked.store(false, Ordering::Release);
        let mut bytes = Vec::new();
        let result = peer.read_to_end(&mut bytes);
        assert!(
            result.is_ok()
                || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
        );
        bytes
    });
    let mut session = reader(stream);
    session.get_mut().deadline = Instant::now() + Duration::from_secs(30);
    assert!(
        read_with_policy(
            session,
            "original",
            Duration::from_secs(30),
            true,
            policy(60),
            None,
            &|| owned.load(Ordering::Acquire),
        )
        .is_err()
    );
    assert!(daemon.join().unwrap().is_empty());
}

#[test]
fn cancelled_backoff_never_returns_permission_to_fall_back() {
    let owned = Arc::new(AtomicBool::new(true));
    let revoked = Arc::clone(&owned);
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.write_all(WAIT.as_bytes()).unwrap();
    let daemon = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        revoked.store(false, Ordering::Release);
        let mut bytes = Vec::new();
        let result = peer.read_to_end(&mut bytes);
        assert!(
            result.is_ok()
                || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
        );
        bytes
    });
    let mut settings = policy(60);
    settings.budget = Duration::from_secs(30);
    settings.initial_delay = Duration::from_secs(10);
    settings.maximum_delay = Duration::from_secs(10);
    assert!(
        read_with_policy(
            reader(stream),
            "must not retry",
            Duration::from_secs(30),
            true,
            settings,
            None,
            &|| owned.load(Ordering::Acquire),
        )
        .is_err()
    );
    assert!(daemon.join().unwrap().is_empty());
}

#[test]
fn buffered_hit_is_not_accepted_after_ownership_is_revoked() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(
        b"first\n{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"capture_protocol\":1}\n",
    )
    .unwrap();
    let mut session = reader(stream);
    let deadline = session.get_ref().deadline;
    assert_eq!(
        read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
        "first\n"
    );
    assert!(
        read_with_policy(
            session,
            "original",
            Duration::from_secs(1),
            true,
            policy(3),
            None,
            &|| false,
        )
        .is_err()
    );
    let result = peer.read(&mut [0; 1]);
    assert!(
        matches!(result, Ok(0))
            || matches!(result, Err(ref e) if e.kind() == io::ErrorKind::ConnectionReset)
    );
}

#[test]
fn partial_owned_frames_survive_poll_timeouts_without_losing_bytes() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        peer.write_all(b"{\"decision\":").unwrap();
        std::thread::sleep(OWNER_POLL * 3);
        peer.write_all(b"\"pass-through\"}\nnext\n").unwrap();
    });
    let mut session = reader(stream);
    let deadline = session.get_ref().deadline;
    assert_eq!(
        read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
        "{\"decision\":\"pass-through\"}\n"
    );
    assert_eq!(session.get_ref().deadline, deadline);
    assert_eq!(
        read_owned_reply(&mut session, 4096, deadline, &|| true).unwrap(),
        "next\n"
    );
    sender.join().unwrap();
}

#[test]
fn ownership_and_absolute_deadline_apply_to_writes_and_buffered_reads() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let mut session = reader(stream);
    let deadline = session.get_ref().deadline;
    assert!(write_owned(&mut session, b"consent\n", deadline, &|| false).is_err());
    assert_eq!(
        write_owned(&mut session, b"consent\n", Instant::now(), &|| true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    peer.set_nonblocking(false).unwrap();
    peer.write_all(b"ok\n").unwrap();
    assert_eq!(
        read_owned_reply(&mut session, 3, deadline, &|| true).unwrap(),
        "ok\n"
    );
    peer.write_all(b"four\n").unwrap();
    assert_eq!(
        read_owned_reply(&mut session, 4, deadline, &|| true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn only_initial_preparation_selects_the_cold_budget() {
    let mut settings = policy(4);
    settings.budget = Duration::ZERO;
    let (result, requests) = exchange(
        vec![PREPARING.to_owned(), WAIT.to_owned(), EXECUTE.to_owned()],
        settings,
    );
    assert!(matches!(result, Ok(Live::Execute { .. })));
    assert_eq!(requests, vec!["original bytes\n"; 2]);
    let (result, requests) = exchange(vec![WAIT.to_owned(), EXECUTE.to_owned()], settings);
    assert!(matches!(result, Ok(Live::PassThrough)));
    assert!(requests.is_empty());
}

#[test]
fn disabled_cold_wait_does_not_disable_keyed_waiting() {
    let mut settings = policy(4);
    settings.preparation_budget = Duration::ZERO;
    let (result, requests) = exchange(vec![PREPARING.to_owned(), EXECUTE.to_owned()], settings);
    assert!(matches!(result, Ok(Live::PassThrough)));
    assert!(requests.is_empty());
    let (result, requests) = exchange(vec![WAIT.to_owned(), EXECUTE.to_owned()], settings);
    assert!(matches!(result, Ok(Live::Execute { .. })));
    assert_eq!(requests, ["original bytes\n"]);
}

#[test]
fn cold_preparation_rolls_over_after_sixty_requests() {
    use std::os::unix::net::UnixListener;
    let base = tempfile::tempdir().unwrap();
    let socket = base.path().join("edge.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let daemon = std::thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut first = BufReader::new(first);
        first.get_mut().write_all(PREPARING.as_bytes()).unwrap();
        for _ in 0..59 {
            let mut request = String::new();
            first.read_line(&mut request).unwrap();
            assert_eq!(request, "original bytes\n");
            first.get_mut().write_all(PREPARING.as_bytes()).unwrap();
        }
        // The first connection's 60 requests have all received their
        // replies before the follower may open a new connection.
        let (second, _) = listener.accept().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut second = BufReader::new(second);
        let mut hello = String::new();
        second.read_line(&mut hello).unwrap();
        assert_eq!(hello.trim_end(), HELLO);
        second
            .get_mut()
            .write_all(b"{\"kind\":\"hello-ok\"}\n")
            .unwrap();
        let mut request = String::new();
        second.read_line(&mut request).unwrap();
        assert_eq!(request, "original bytes\n");
        second.get_mut().write_all(EXECUTE.as_bytes()).unwrap();
    });
    let client = UnixStream::connect(&socket).unwrap();
    let mut settings = policy(70);
    settings.budget = Duration::from_secs(8);
    settings.preparation_budget = Duration::from_secs(8);
    let result = read_with_policy(
        reader(client),
        "original bytes",
        Duration::from_secs(1),
        true,
        settings,
        Some((socket.to_str().unwrap(), Duration::from_secs(1))),
        &|| true,
    );
    assert!(matches!(result, Ok(Live::Execute { .. })));
    daemon.join().unwrap();
}
