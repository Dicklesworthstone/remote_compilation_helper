use super::*;
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

fn reply(result: Result<Decided, WorkError>) -> Value {
    let Decided::Reply(text) = result.unwrap() else {
        panic!("capacity cannot return an execution, hit, or shadow observation");
    };
    serde_json::from_str(&text).unwrap()
}

fn assert_capacity(value: &Value, negotiated: bool) {
    assert_eq!(value["kind"], "rustc-decision");
    assert_eq!(value["decision"], "pass-through");
    assert_eq!(value["reason"], "edge-capacity");
    if negotiated {
        assert_eq!(value["retry"], "decision-capacity-v1");
        assert_eq!(value["compiler_skip_authorized"], false);
        assert_eq!(value["materialization_started"], false);
        assert_eq!(value.as_object().unwrap().len(), 6);
    } else {
        assert!(value.get("retry").is_none());
    }
    for absent in ["action_key", "attempt", "env"] {
        assert!(value.get(absent).is_none());
    }
}

#[test]
fn saturated_decisions_do_not_run_and_release_no_other_callers_permit() {
    let lane = Limit::new(1);
    let occupied = lane.acquire().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for negotiated in [false, true] {
        let called = Arc::clone(&calls);
        let answer = block_on_top_level(
            &runtime,
            on_lane(&lane, negotiated, move || {
                called.fetch_add(1, Ordering::SeqCst);
                Decided::Reply("must never run".into())
            }),
        );
        assert_capacity(&reply(answer), negotiated);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(lane.acquire().is_none());
    }
    drop(occupied);
    let called = Arc::clone(&calls);
    let answer = block_on_top_level(
        &runtime,
        on_lane(&lane, true, move || {
            called.fetch_add(1, Ordering::SeqCst);
            Decided::Reply("{\"actual_decision\":true}".into())
        }),
    );
    assert_eq!(reply(answer), json!({"actual_decision":true}));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(lane.acquire().is_some());
}

#[test]
fn admitted_panic_is_not_relabelled_as_a_safe_capacity_wait() {
    let lane = Limit::new(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&calls);
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let answer = block_on_top_level(
        &runtime,
        on_lane(&lane, true, move || {
            called.fetch_add(1, Ordering::SeqCst);
            panic!("injected failure after admission");
        }),
    );
    assert!(matches!(answer, Err(WorkError::Panicked)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(lane.acquire().is_some());
}

#[test]
fn only_boolean_wait_negotiation_produces_the_capacity_hint() {
    use crate::coord::live::CoordLive;
    use crate::coord::live_dependency::LiveDependencyLane;
    let coord = Arc::new(CoordLive::new());
    let live = Arc::new(LiveEdge::new(LiveDependencyLane::new(coord)));
    let lane = Limit::new(0);
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for flag in [
        None,
        Some(json!(null)),
        Some(json!(false)),
        Some(json!(1)),
        Some(json!("true")),
        Some(json!(true)),
    ] {
        let negotiated = flag == Some(json!(true));
        let mut request =
            json!({"kind":"rustc-request", "argv":["/never-run"], "cwd":"/missing", "env":[]});
        if let Some(flag) = flag {
            request["wait_for_inflight"] = flag;
        }
        assert_capacity(
            &reply(block_on_top_level(
                &runtime,
                decide(&lane, Arc::clone(&live), request),
            )),
            negotiated,
        );
    }
}

#[test]
fn running_connection_retries_after_saturation_without_starving_status() {
    use super::super::{EdgeLimits, EdgeServices, LIVE_DECISION_WORKERS, handle_connection};
    use crate::coord::live::CoordLive;
    use crate::coord::live_dependency::LiveDependencyLane;
    use crate::edge::shadow::ShadowPlane;
    use asupersync::net::unix::UnixListener;
    use rabs_protocol::socket_admission::{AdmissionPolicy, SocketMetadata};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    // Real connection handler, admission, framing and blocking lane. The
    // request is a compiler probe, so after capacity returns its actual normal
    // path is shadow observation; this fixture never claims a compiled cache hit.
    let temporary = crate::test_util::private_tempdir();
    let socket = temporary.path().join("edge.sock");
    let receipts = temporary.path().join("shadow-receipts.ndjson");
    let coord = Arc::new(CoordLive::new());
    coord.mark_up();
    let services = EdgeServices {
        shadow: Arc::new(std::sync::Mutex::new(
            ShadowPlane::open(temporary.path()).unwrap(),
        )),
        coord: coord.edge_subscriber(),
        prepared_operations: None,
        live: Some(Arc::new(LiveEdge::new(LiveDependencyLane::new(
            Arc::clone(&coord),
        )))),
    };
    let limits = EdgeLimits::new(0);
    let occupied: Vec<_> = (0..LIVE_DECISION_WORKERS)
        .map(|_| limits.live.acquire().unwrap())
        .collect();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    block_on_top_level(&runtime, async {
        let listener = UnixListener::bind(&socket).await.unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = std::fs::metadata(&socket).unwrap();
        let peer = std::thread::spawn(move || {
            let stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream = BufReader::new(stream);
            let exchange =
                |stream: &mut BufReader<std::os::unix::net::UnixStream>, value: &Value| -> Value {
                    writeln!(stream.get_mut(), "{value}").unwrap();
                    let mut line = String::new();
                    assert!(stream.read_line(&mut line).unwrap() > 0);
                    serde_json::from_str(&line).unwrap()
                };
            assert_eq!(
                exchange(
                    &mut stream,
                    &json!({
                        "kind":"hello", "transport":{"minimum_compatible":1,"current":1},
                        "application":{"minimum_compatible":1,"current":1},
                    })
                )["kind"],
                "hello-ok"
            );
            let request = json!({"kind":"rustc-request", "argv":["/never-run", "-vV"],
                "cwd":"/missing", "env":[], "wait_for_inflight":true});
            assert_capacity(&exchange(&mut stream, &request), true);
            assert!(
                !receipts.exists(),
                "saturated admission ran the observation"
            );
            assert_eq!(
                exchange(&mut stream, &json!({"kind":"status"}))["kind"],
                "coord-status"
            );
            drop(occupied);
            let normal = exchange(&mut stream, &request);
            assert_eq!(normal["decision"], "pass-through");
            assert!(normal.get("retry").is_none());
            assert_eq!(normal["mode"], "shadow");
            assert_eq!(
                std::fs::read_to_string(receipts).unwrap().lines().count(),
                1
            );
        });
        let (stream, _) = listener.accept().await.unwrap();
        handle_connection(
            1,
            stream,
            AdmissionPolicy {
                expected_uid: metadata.uid(),
                require_token_on_unix: false,
                tcp_enabled: false,
            },
            SocketMetadata {
                owner_uid: metadata.uid(),
                mode: 0o600,
            },
            services,
            limits,
        )
        .await;
        peer.join().unwrap();
    });
    let status: Value = serde_json::from_str(&coord.edge_subscriber().status_json()).unwrap();
    assert_eq!(status["open_flights"], 0);
}
