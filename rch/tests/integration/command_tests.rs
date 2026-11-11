use std::process::Command;

use super::common::{assert_contains, init_test_logging};

/// Actual CLI exits and IPC, with explicitly local SSH transport fixtures.
/// Each worker has real, separate paths and executes the compiled namespace
/// registry, path validator and admission retry script. This is not a live SSH
/// fleet or controller-lifecycle qualification (source_namespace_control owns
/// that suite). The compatible worker deliberately stops at source admission;
/// no synthetic compiler success is asserted.
#[cfg(target_os = "linux")]
mod source_topology_cli {
    use rch_common::{SourceTopology, SourceTopologyMismatch};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Layout {
        Conflict,
        Busy,
        Alternate,
        AlternateBusy,
    }

    #[derive(Clone, Default)]
    struct PeerState {
        requests: Vec<String>,
        selections: Vec<String>,
        releases: Vec<Value>,
        cached: Option<SourceTopologyMismatch>,
        builds: BTreeMap<u64, (String, String)>,
    }

    struct Fixture {
        root: tempfile::TempDir,
        project: PathBuf,
        topology: SourceTopology,
        state: Arc<Mutex<PeerState>>,
        stop: Arc<AtomicBool>,
        server: Option<JoinHandle<()>>,
    }

    impl Fixture {
        fn new(layout: Layout) -> Self {
            // Offloaded tests set TMPDIR inside the synced Git checkout. This
            // fixture executes the real live-checkout guard, so its worker
            // paths must live outside that checkout rather than inherit it.
            // An OS temp directory may itself be Git-marked on a shared host.
            let temporary_parent = ["/tmp", "/var/tmp"]
                .into_iter()
                .filter_map(|path| std::fs::canonicalize(path).ok())
                .find(|parent| {
                    parent.ancestors().all(|ancestor| {
                        matches!(
                            std::fs::symlink_metadata(ancestor.join(".git")),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound
                        )
                    })
                })
                .expect("source topology CLI fixture needs an OS temp directory outside Git");
            let root = tempfile::Builder::new()
                .prefix("rch-source-topology-")
                .tempdir_in(temporary_parent)
                .expect("create source topology CLI fixture outside the synced checkout");
            let base = root.path().canonicalize().unwrap();
            for ancestor in base.ancestors() {
                match std::fs::symlink_metadata(ancestor.join(".git")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => panic!(
                        "source topology CLI fixture has Git checkout ancestor {}; \
                         the real live-checkout guard must remain enabled",
                        ancestor.display()
                    ),
                    Err(error) => panic!(
                        "cannot verify source topology CLI fixture ancestor {}: {error}",
                        ancestor.display()
                    ),
                }
            }
            let project = base.join("projects/app");
            for directory in ["home", "config", "state", "bin", "projects/app/src"] {
                std::fs::create_dir_all(base.join(directory)).unwrap();
            }
            std::fs::write(
                project.join("Cargo.toml"),
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .unwrap();
            std::fs::write(project.join("src/lib.rs"), "").unwrap();
            symlink(base.join("projects"), base.join("alias")).unwrap();
            let topology = SourceTopology {
                canonical_root: base.join("projects").to_string_lossy().into_owned(),
                alias_root: base.join("alias").to_string_lossy().into_owned(),
            };
            let socket = base.join("daemon.sock");
            std::fs::write(
                base.join("config/config.toml"),
                format!(
                    "[general]\nsocket_path = {:?}\nforce_remote = true\n\
                 [self_healing]\nhook_starts_daemon = false\n\
                 [compilation]\nallow_local_fallback = true\nlocal_slots = 0\n\
                 [transfer]\nssh_control_persist_secs = 0\n\
                 [path_topology]\ncanonical_root = {:?}\nalias_root = {:?}\n\
                 [output]\nvisibility = \"none\"\n",
                    socket.to_str().unwrap(),
                    topology.canonical_root,
                    topology.alias_root,
                ),
            )
            .unwrap();
            std::fs::write(base.join("config/workers.toml"), "workers = []\n").unwrap();
            let local_command = base.join("bin/cargo");
            std::fs::write(
                &local_command,
                // The real planner first tries read-only locked metadata,
                // then parses these dependency-free manifests when Cargo
                // refuses a missing lock. Only workload execution is forbidden.
                "#!/bin/sh\n\
                 if [ \"${1-}\" = metadata ] && [ \"${2-}\" = --locked ]; then exit 101; fi\n\
                 printf 'local command ran\\n' > \"$RCH_TOPOLOGY_FIXTURE/local-ran\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&local_command, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let ssh = base.join("bin/ssh");
            std::fs::write(&ssh, SSH_FIXTURE).unwrap();
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(
                base.join("paths.sh"),
                include_str!("../../src/hook/source_namespace_paths.sh"),
            )
            .unwrap();
            std::fs::write(
                base.join("admission.sh"),
                include_str!("../../src/hook/source_claim_admission.sh"),
            )
            .unwrap();
            std::fs::write(
                base.join("registry.sh"),
                format!(
                    "{}\n{}\n{}",
                    rch_common::wkr_locate::WKR_LOCATE_SHELL,
                    rch_common::stale_target_reap::SOURCE_CLAIM_RECORD_HELPERS,
                    include_str!("../../src/hook/source_claim_registry.sh")
                ),
            )
            .unwrap();
            for worker in ["bad", "good"] {
                let directory = base.join(worker);
                std::fs::create_dir_all(directory.join("canonical")).unwrap();
                std::fs::write(directory.join("live-checkouts"), "").unwrap();
                if worker == "bad" && layout != Layout::Busy {
                    std::fs::create_dir_all(directory.join("physical")).unwrap();
                    symlink(directory.join("physical"), directory.join("alias")).unwrap();
                    std::fs::write(
                        directory.join("physical/keep"),
                        b"private worker source contents",
                    )
                    .unwrap();
                } else if worker == "good" {
                    symlink(directory.join("canonical"), directory.join("alias")).unwrap();
                }
            }
            if layout == Layout::Busy {
                std::fs::write(base.join("bad/hold-source"), "").unwrap();
            }
            let state = Arc::new(Mutex::new(PeerState::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let server_state = state.clone();
            let server_stop = stop.clone();
            let server_topology = topology.clone();
            let server = thread::spawn(move || {
                while !server_stop.load(Ordering::Acquire) {
                    let (stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("accept fixture connection: {error}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let route = line.trim_end().to_owned();
                    let mut state = server_state.lock().unwrap();
                    state.requests.push(route.clone());
                    let reply = if route == "GET /restart-admission" {
                        json!({"admission_closed": false})
                    } else if route.starts_with("GET /select-worker") {
                        let query = parameters(&route);
                        let requested: SourceTopology =
                            serde_json::from_str(&query["source_topology"]).unwrap();
                        assert_eq!(requested, server_topology);
                        let worker = query.get("worker").cloned().unwrap_or_else(|| {
                            if state.cached.is_some()
                                && matches!(layout, Layout::Alternate | Layout::AlternateBusy)
                            {
                                "good".into()
                            } else {
                                "bad".into()
                            }
                        });
                        state.selections.push(worker.clone());
                        if worker == "good" && layout == Layout::AlternateBusy {
                            json!({"worker": null, "reason": "all_workers_busy"})
                        } else if let Some(mismatch) =
                            state.cached.as_ref().filter(|_| worker == "bad")
                        {
                            cached_refusal(mismatch)
                        } else {
                            let build = 40 + state.selections.len() as u64;
                            state
                                .builds
                                .insert(build, (worker.clone(), query["local_wrapper_id"].clone()));
                            json!({"worker": {
                                "id": worker, "host": format!("fixture-{worker}.invalid"),
                                "user": "fixture", "identity_file": "/fixture-key",
                                "slots_available": 4, "speed_score": 80.0,
                            }, "reason": "success", "build_id": build})
                        }
                    } else if route.starts_with("POST /release-worker?") {
                        let query = parameters(&route);
                        if let Some(encoded) = query.get("worker_source_topology_mismatch") {
                            let mismatch: SourceTopologyMismatch =
                                serde_json::from_str(encoded).unwrap();
                            mismatch.validate().unwrap();
                            assert_eq!(mismatch.topology, server_topology);
                            state.cached = Some(mismatch);
                        }
                        state.releases.push(serde_json::to_value(query).unwrap());
                        json!({"status": "ok"})
                    } else if let Some(build_route) = route.strip_prefix("GET /builds/") {
                        let id = build_route
                            .split('?')
                            .next()
                            .unwrap()
                            .parse::<u64>()
                            .unwrap();
                        let (worker, wrapper) = &state.builds[&id];
                        json!({"status": "completed", "local_wrapper_id": wrapper,
                            "record": {"id": id, "worker_id": worker, "exit_code": 1}})
                    } else if route == "POST /build-heartbeat" {
                        let mut body = String::new();
                        reader.read_line(&mut body).unwrap();
                        let heartbeat: Value = serde_json::from_str(&body).unwrap();
                        json!({"status": "ok", "build_id": heartbeat["build_id"],
                            "worker_id": heartbeat["worker_id"], "phase": heartbeat["phase"]})
                    } else if route == "GET /status" {
                        status_reply(layout, state.cached.as_ref())
                    } else if route == "GET /workers/capabilities" {
                        json!({"workers": [{"id": "bad", "host": "fixture-bad.invalid",
                            "user": "fixture", "capabilities": {},
                            "source_topology_mismatches": state.cached.iter().collect::<Vec<_>>()
                        }]})
                    } else if route.starts_with("POST /workers/")
                        && route.contains("process-observation")
                    {
                        json!({"status": "ok"})
                    } else {
                        panic!("unexpected fixture request {route}");
                    };
                    drop(state);
                    write!(
                        reader.get_mut(),
                        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{reply}\n"
                    )
                    .unwrap();
                }
            });
            Self {
                root,
                project,
                topology,
                state,
                stop,
                server: Some(server),
            }
        }

        fn command(&self) -> Command {
            let base = self.root.path();
            let path = std::env::join_paths([
                base.join("bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ])
            .unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_rch"));
            command
                .env_clear()
                .env("PATH", path)
                .env("HOME", base.join("home"))
                .env("RCH_CONFIG_DIR", base.join("config"))
                .env("RCH_STATE_HOME", base.join("state"))
                .env("XDG_CACHE_HOME", base.join("cache"))
                .env("RCH_TOPOLOGY_FIXTURE", base)
                .env(
                    "RCH_WKR_BIN",
                    std::env::var_os("RCH_WKR_BIN")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(env!("CARGO_BIN_EXE_rch")).with_file_name("rch-wkr")
                        }),
                )
                .env("RCH_DISABLE_CONFIG_CACHE", "1")
                .env("RCH_NO_UPDATE_CHECK", "1")
                .env("RCH_QUEUE_WHEN_BUSY", "0")
                .env("RCH_RESTART_ADMISSION_WAIT_SECS", "0")
                .env("RUSTUP_TOOLCHAIN", "stable")
                .env("NO_COLOR", "1")
                .current_dir(&self.project)
                .args(["--no-self-healing", "--json", "--format=json"]);
            command
        }

        fn run(&self, pinned: bool, require_remote: bool) -> Output {
            let mut command = self.command();
            command
                .env("RCH_REQUIRE_REMOTE", if require_remote { "1" } else { "0" })
                .arg("exec");
            if pinned {
                command.args(["--worker", "bad"]);
            }
            command.args(["--", "cargo", "check"]).output().unwrap()
        }

        fn events(&self) -> Vec<Value> {
            std::fs::read_to_string(self.root.path().join("ssh-events.jsonl"))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        fn assert_no_local(&self) {
            assert!(
                !self.root.path().join("local-ran").exists(),
                "workload ran locally"
            );
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(server) = self.server.take() {
                let result = server.join();
                if !std::thread::panicking() {
                    result.unwrap();
                }
            }
        }
    }

    fn parameters(route: &str) -> BTreeMap<String, String> {
        route
            .split_once('?')
            .unwrap()
            .1
            .split('&')
            .map(|part| {
                let (key, value) = part.split_once('=').unwrap();
                (
                    key.to_owned(),
                    urlencoding::decode(value).unwrap().into_owned(),
                )
            })
            .collect()
    }

    fn cached_refusal(mismatch: &SourceTopologyMismatch) -> Value {
        json!({"worker": null, "reason": "source_topology_incompatible", "diagnostics": {
            "required_runtime": "rust", "estimated_cores": 1, "min_success_rate": 0.0,
            "fallback_min_success_rate": 0.0, "active_project_exclusion_count": 0,
            "workers": [{"worker_id": "bad", "status": "healthy", "circuit_state": "closed",
                "pressure_state": "healthy", "pressure_reason_code": "ok", "success_rate": 1.0,
                "min_success_rate": 0.0, "fallback_min_success_rate": 0.0,
                "required_runtime": "rust", "runtime_available": true, "available_slots": 4,
                "total_slots": 4, "estimated_cores": 1, "active_project_excluded": false,
                "final_decision": "deny", "final_reason": format!("{mismatch:?}"),
                "reason_codes": ["topology.source_incompatible"]}]
        }})
    }

    fn status_reply(layout: Layout, mismatch: Option<&SourceTopologyMismatch>) -> Value {
        let ids = if matches!(layout, Layout::Alternate | Layout::AlternateBusy) {
            vec!["bad", "good"]
        } else {
            vec!["bad"]
        };
        json!({"daemon": {"pid": 1, "uptime_secs": 1, "version": "fixture",
            "socket_path": "fixture", "started_at": "fixture", "workers_total": ids.len(),
            "workers_healthy": ids.len(), "slots_total": 8, "slots_available": 8},
            "workers": ids.iter().map(|id| json!({"id": id, "host": format!("fixture-{id}.invalid"),
                "user": "fixture", "status": "healthy", "circuit_state": "closed",
                "used_slots": 0, "total_slots": 4, "speed_score": 80.0, "last_error": null,
                "source_topology_mismatches": mismatch.filter(|_| *id == "bad").into_iter().collect::<Vec<_>>()
            })).collect::<Vec<_>>(),
            "active_builds": [], "recent_builds": [], "issues": [],
            "stats": {"total_builds": 0, "success_count": 0, "failure_count": 0,
                "remote_count": 0, "local_count": 0, "avg_duration_ms": 0}})
    }

    fn envelope(output: &Output) -> Value {
        let text = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(
            text.lines()
                .rev()
                .find(|line| !line.is_empty())
                .unwrap_or_else(|| {
                    panic!(
                        "missing CLI result: stderr={}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                }),
        )
        .unwrap()
    }

    #[test]
    fn source_topology_cli_conflict_is_permanent_even_when_local_fallback_is_allowed() {
        for (pinned, required) in [(true, true), (false, true), (false, false)] {
            let fixture = Fixture::new(Layout::Conflict);
            let output = fixture.run(pinned, required);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            let result = envelope(&output);
            assert_eq!(result["outcome"], "refused", "{result}");
            assert_eq!(result["worker_id"], "bad");
            assert_eq!(result["error_code"], "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE");
            assert!(
                stderr.contains("bad") && stderr.contains(&fixture.topology.alias_root),
                "{stderr}"
            );
            assert!(
                stderr.contains("physical") && stderr.contains("compatible"),
                "{stderr}"
            );
            assert!(!stderr.contains("retryable"), "{stderr}");
            assert!(
                !stderr.contains("private worker source contents"),
                "{stderr}"
            );
            fixture.assert_no_local();
            let events = fixture.events();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["phase"] == "namespace")
                    .count(),
                1,
                "{events:?}"
            );
            assert_eq!(
                events
                    .iter()
                    .find(|event| event["phase"] == "namespace")
                    .unwrap()["status"],
                73
            );
            assert_eq!(
                std::fs::read_to_string(fixture.root.path().join("bad/attempts"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
            let state = fixture.state.lock().unwrap();
            assert_eq!(state.selections, ["bad"]);
            assert_eq!(state.releases.len(), 1);
            assert!(state.releases[0]["worker_source_topology_mismatch"].is_string());
            assert!(state.releases[0].get("worker_source_busy").is_none());
        }
    }

    #[test]
    fn source_topology_cli_cached_refusal_does_not_contact_incompatible_worker_again() {
        let fixture = Fixture::new(Layout::Conflict);
        let first = fixture.run(true, true);
        assert_eq!(
            first.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(
            envelope(&first)["error_code"],
            "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE"
        );
        let events = fixture.events();
        let second = fixture.run(true, true);
        assert_eq!(
            second.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(envelope(&second)["outcome"], "refused");
        assert_eq!(
            envelope(&second)["error_code"],
            "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE"
        );
        let diagnostic = String::from_utf8_lossy(&second.stderr);
        assert!(diagnostic.contains("bad"), "{diagnostic}");
        assert!(
            diagnostic.contains(&fixture.topology.canonical_root),
            "{diagnostic}"
        );
        assert_eq!(fixture.events(), events);
        fixture.assert_no_local();
        assert_eq!(fixture.state.lock().unwrap().selections, ["bad", "bad"]);

        // Exercise the actual operator-facing CLI serialization of the same
        // saved refusal. Durable daemon storage is covered by daemon tests.
        let capabilities = fixture
            .command()
            .args(["workers", "capabilities"])
            .output()
            .unwrap();
        assert!(
            capabilities.status.success(),
            "{}",
            String::from_utf8_lossy(&capabilities.stderr)
        );
        let report: Value = serde_json::from_slice(&capabilities.stdout).unwrap();
        assert_eq!(report["success"], true, "{report}");
        let worker = &report["data"]["workers"][0];
        assert_eq!(worker["id"], "bad", "{report}");
        let saved = fixture.state.lock().unwrap().cached.clone().unwrap();
        let reported: SourceTopologyMismatch =
            serde_json::from_value(worker["source_topology_mismatches"][0].clone()).unwrap();
        assert_eq!(reported, saved);
        assert_eq!(reported.topology, fixture.topology);
        assert!(reported.detail.contains("canonical_physical="));
        assert!(reported.detail.contains("alias_physical="));
        assert!(reported.detail.contains("/physical"));
        assert!(
            !report
                .to_string()
                .contains("private worker source contents")
        );
        assert_eq!(fixture.events(), events);
        fixture.assert_no_local();
    }

    #[test]
    fn source_topology_cli_temporary_ownership_keeps_retryable_exit_103() {
        let fixture = Fixture::new(Layout::Busy);
        let output = fixture.run(true, true);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(103), "{stderr}");
        assert_eq!(envelope(&output)["outcome"], "refused");
        assert!(stderr.contains("retryable"), "{stderr}");
        let events = fixture.events();
        assert_eq!(
            events
                .iter()
                .find(|event| event["phase"] == "namespace")
                .unwrap()["status"],
            75
        );
        let attempts = std::fs::read_to_string(fixture.root.path().join("bad/attempts")).unwrap();
        // An elapsed window permits a variable number of registry transactions.
        assert!(attempts.lines().count() >= 1, "{attempts}");
        let state = fixture.state.lock().unwrap();
        assert!(state.cached.is_none());
        assert_eq!(state.releases[0]["worker_source_busy"], "1");
        assert!(
            state.releases[0]
                .get("worker_source_topology_mismatch")
                .is_none()
        );
        fixture.assert_no_local();
    }

    #[test]
    fn source_topology_cli_failover_accepts_different_compatible_worker_layout() {
        let fixture = Fixture::new(Layout::Alternate);
        let output = fixture.run(false, true);
        assert!(
            !output.status.success(),
            "fixture intentionally stops before source admission"
        );
        let events = fixture.events();
        let namespaces = events
            .iter()
            .filter(|event| event["phase"] == "namespace")
            .collect::<Vec<_>>();
        assert_eq!(
            namespaces.len(),
            2,
            "stderr={} events={events:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(namespaces[0]["worker"], "bad");
        assert_eq!(namespaces[0]["status"], 73);
        assert_eq!(namespaces[1]["worker"], "good");
        assert_eq!(namespaces[1]["status"], 0);
        assert!(events.iter().any(
            |event| event["worker"] == "good" && event["phase"] == "source_admission_boundary"
        ));
        assert_eq!(fixture.state.lock().unwrap().selections, ["bad", "good"]);
        assert_eq!(
            std::fs::canonicalize(fixture.root.path().join("good/alias")).unwrap(),
            fixture.root.path().join("good/canonical")
        );
        fixture.assert_no_local();
    }

    #[test]
    fn source_topology_cli_busy_alternative_retries_without_repeating_incompatible_worker() {
        let fixture = Fixture::new(Layout::AlternateBusy);
        for _ in 0..2 {
            let output = fixture.run(false, true);
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(103), "{diagnostic}");
            assert_eq!(envelope(&output)["outcome"], "refused");
            fixture.assert_no_local();
        }
        let events = fixture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["phase"] == "namespace")
                .count(),
            1,
            "{events:?}"
        );
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.selections, ["bad", "good", "good"]);
        assert!(state.cached.is_some());
        assert_eq!(state.releases.len(), 1);
        drop(state);

        // A relocation attempt follows the same no-local rule even when the
        // original invocation allowed ordinary local fallbacks.
        let fixture = Fixture::new(Layout::AlternateBusy);
        let output = fixture.run(false, false);
        assert_eq!(
            output.status.code(),
            Some(103),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.assert_no_local();
    }

    const SSH_FIXTURE: &str = r#"#!/usr/bin/env python3
import hashlib, json, os, pathlib, shlex, subprocess, sys
base = pathlib.Path(os.environ['RCH_TOPOLOGY_FIXTURE'])
destination = next((arg for arg in sys.argv[1:] if arg.startswith('fixture@fixture-')), None)
if destination not in ('fixture@fixture-bad.invalid', 'fixture@fixture-good.invalid'):
    sys.exit('unexpected fixture SSH destination')
worker = 'bad' if destination.endswith('-bad.invalid') else 'good'
root = base / worker
canonical, alias = root / 'canonical', root / 'alias'
def event(phase, status):
    with (base / 'ssh-events.jsonl').open('a') as stream:
        stream.write(json.dumps(dict(worker=worker, phase=phase, status=status)) + '\n')
first = sys.stdin.buffer.readline()
timing_prefix = b''
if first.startswith(b'export RCH_TIMING_SCALE='):
    assert first.endswith(b';\n'), 'invalid transported timing header'
    value = first[len(b'export RCH_TIMING_SCALE='):-2].decode('ascii')
    assert 1.0 <= float(value) <= 10.0, 'invalid transported timing scale'
    os.environ['RCH_TIMING_SCALE'] = value
    timing_prefix = first
    first = sys.stdin.buffer.readline()
if first == b'{\n':
    second = sys.stdin.buffer.readline()
    if second != b'(\n':
        # A source holder keeps stdin open for heartbeat/release frames. Identify
        # its actual transport header without waiting for EOF or issuing a grant.
        header = (second, sys.stdin.buffer.readline())
        assert header == (b'set -eu\n', b"exec 3<<'RCH_SOURCE_LOCK_SESSION_PROGRAM'\n"), header
        event('source_admission_boundary', 73)
        print('RCH fixture stopped after namespace: source admission intentionally unavailable', file=sys.stderr)
        sys.exit(73)
    # The namespace RPC batches its live-checkout guard into one compound.
    first += second
payload = timing_prefix.decode() + first.decode() + sys.stdin.buffer.read().decode()
batched = first == b'{\n(\n'
if batched:
    assert payload.count('RCH_SYNC_LIVE_CHECKOUT_REFUSED:') == 1, 'namespace RPC lost its guard'
if payload.startswith('(set -eu\nrch_destination='):
    # Execute the production read-only guard against the worker's mapped
    # fixture root and host marker, rather than accepting every control RPC.
    assert 'RCH_SYNC_LIVE_CHECKOUT_REFUSED:' in payload
    assert payload.count('/etc/rch/live-checkouts') == 1
    lines = payload.splitlines(keepends=True)
    destination = pathlib.Path(shlex.split(lines[1].split('=', 1)[1])[0])
    relative = destination.relative_to(base / 'projects')
    lines[1] = 'rch_destination=' + shlex.quote(str(canonical / relative)) + '\n'
    guard = ''.join(lines).replace('/etc/rch/live-checkouts', shlex.quote(str(root / 'live-checkouts')))
    result = subprocess.run(['sh', '-s'], input=guard.encode(), capture_output=True, timeout=5)
    event('live_checkout_guard', result.returncode)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.returncode)
if 'RCH_TOPOLOGY_INITIALIZATION_REQUIRED' in payload:
    present = all(os.path.lexists(path) for path in (canonical, alias))
    print('RCH_TOPOLOGY_PATHS_PRESENT' if present else 'RCH_TOPOLOGY_INITIALIZATION_REQUIRED',
          file=sys.stderr if batched else sys.stdout)
    event('probe', 0)
    # Batched, the observation is a diagnostic: the initializer still runs.
    if not batched:
        sys.exit(0)
if 'RCH_NAMESPACE_SCOPE' not in payload:
    event('unexpected_control_command', 73)
    sys.exit('unexpected fixture SSH control command')
paths = (base / 'paths.sh').read_text()
assert 'RCH_SOURCE_TOPOLOGY_INCOMPATIBLE' in payload, 'missing namespace refusal protocol'
registry = root / 'registry'
for name in ('', 'released', 'cancelled', 'quarantine'):
    (registry / name).mkdir(parents=True, exist_ok=True)
lock = registry / 'metadata.lock'
lock.touch(exist_ok=True)
roots = ('\n'.join(sorted(set(map(str, (canonical, alias))))) + '\n').encode()
digest = hashlib.sha256(roots).hexdigest()
program = (base / 'registry.sh').read_text()
def command(operation, identity, *extra):
    return ['flock', '-x', str(lock), 'sh', '-c', program, 'rch-fixture-registry',
            str(registry), identity, digest, operation, *extra]
if (root / 'hold-source').exists() and not (root / 'seeded').exists():
    seeded = subprocess.run(command('acquire', 'a1'), input=roots, capture_output=True, timeout=5)
    if seeded.returncode:
        sys.stderr.buffer.write(seeded.stderr)
        sys.exit(seeded.returncode)
    (root / 'seeded').touch()
arguments = ' '.join(shlex.quote(str(path)) for path in (canonical, alias))
check = 'set -- check ' + arguments + '\n' + paths
create = 'set -- create ' + arguments + '\n' + paths
attempt = command('topology', 'b1', check, create)
script = ('rch_source_attempt() { (\nset -eu\nprintf "attempt\\n" >> '
          + shlex.quote(str(root / 'attempts')) + '\nexec ' + shlex.join(attempt)
          + " <<'RCH_FIXTURE_ROOTS'\n" + roots.decode() + 'RCH_FIXTURE_ROOTS\n); }\n'
          + 'rch_admission_retry_seconds=5\n' + (base / 'admission.sh').read_text())
result = subprocess.run(['sh', '-c', script], capture_output=True, timeout=10)
event('namespace', result.returncode)
sys.stdout.buffer.write(result.stdout)
# The adapter maps one logical remote pathname namespace onto each local
# worker directory. Translate only the validated logical labels in its real
# path diagnostic; preserve the actual observed physical roots and verdict.
for line in result.stderr.decode().splitlines():
    if line.startswith('RCH_SOURCE_TOPOLOGY_PATHS '):
        mapping = json.loads(line.removeprefix('RCH_SOURCE_TOPOLOGY_PATHS '))
        assert mapping['canonical'] == str(canonical) and mapping['alias'] == str(alias)
        mapping['canonical'] = str(base / 'projects')
        mapping['alias'] = str(base / 'alias')
        line = 'RCH_SOURCE_TOPOLOGY_PATHS ' + json.dumps(mapping, ensure_ascii=True)
    print(line, file=sys.stderr)
sys.exit(result.returncode)
"#;
}

#[cfg(unix)]
#[test]
fn shim_status_reports_actual_path_interception_and_absolute_toolchain_gap() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let shim_dir = home.join(".rch/shims");
    let delegator_dir = home.join(".local/bin");
    let real_dir = home.join(".cargo/bin");
    let nonexec_dir = home.join("nonexec");
    let toolchains = home.join(".rustup/toolchains");
    let toolchain_bin = toolchains.join("fixture-toolchain/bin");
    let config_dir = home.join("config");
    for dir in [
        &shim_dir,
        &delegator_dir,
        &real_dir,
        &nonexec_dir,
        &toolchain_bin,
        &config_dir,
    ] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let executable = |path: &std::path::Path, body: &str| {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // Harmless executables distinguish which path a real shell takes. They do
    // not compile or stand in for evidence of actual remote offloading.
    executable(
        &shim_dir.join("cargo"),
        "#!/bin/sh\n# rch-shim-version: 4\nprintf 'intercepted\\n'\n",
    );
    executable(
        &delegator_dir.join("cargo"),
        "#!/bin/sh\nSHIM=\"$HOME/.rch/shims/cargo\"\nif [ -x \"$SHIM\" ]; then exec \"$SHIM\" \"$@\"; fi\nexec \"$HOME/.cargo/bin/cargo\" \"$@\"\n",
    );
    for dir in [real_dir.as_path(), &toolchain_bin, home] {
        executable(&dir.join("cargo"), "#!/bin/sh\nprintf 'real\\n'\n");
    }
    let nonexec = nonexec_dir.join("cargo");
    std::fs::write(&nonexec, "not an executable cargo").unwrap();
    std::fs::set_permissions(&nonexec, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[general]\nenabled = true\n",
    )
    .unwrap();
    std::fs::write(config_dir.join("workers.toml"), "workers = []\n").unwrap();

    for (first, expected, shell_output, human_message) in [
        (
            shim_dir.as_path(),
            "direct",
            "intercepted\n",
            "PATH resolves the shim ahead",
        ),
        (
            &nonexec_dir,
            "direct",
            "intercepted\n",
            "PATH resolves the shim ahead",
        ),
        (
            &delegator_dir,
            "delegated",
            "intercepted\n",
            "cargo IS intercepted",
        ),
        (
            &real_dir,
            "none",
            "real\n",
            "cargo is not being intercepted",
        ),
        (
            std::path::Path::new(""),
            "none",
            "real\n",
            "cargo is not being intercepted",
        ),
    ] {
        let path = std::env::join_paths([first, &shim_dir, &real_dir]).unwrap();
        let actual = Command::new("/bin/sh")
            .args(["-c", "cargo"])
            .env_clear()
            .env("HOME", home)
            .env("PATH", &path)
            .current_dir(home)
            .output()
            .unwrap();
        assert!(actual.status.success(), "{expected}: {actual:?}");
        assert_eq!(actual.stdout, shell_output.as_bytes(), "{expected}");

        for machine in [true, false] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_rch"));
            command
                .env_clear()
                .env("HOME", home)
                .env("PATH", &path)
                .env("RUSTUP_HOME", home.join(".rustup"))
                .env("RCH_CONFIG_DIR", &config_dir)
                .env("XDG_CACHE_HOME", home.join("cache"))
                .env("NO_COLOR", "1")
                .current_dir(home)
                .arg("--no-self-healing");
            if machine {
                command.args(["--json", "--format=json"]);
            }
            let output = command.args(["shim", "status"]).output().unwrap();
            assert!(output.status.success(), "{expected}: {output:?}");
            if machine {
                let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(status["installed"], true, "{status}");
                assert_eq!(status["interception"], expected, "{status}");
                assert_eq!(status["on_path_ahead_of_cargo"], expected != "none");
                assert_eq!(status["toolchains_wrapped"], 0, "{status}");
                assert_eq!(status["toolchains_total"], 1, "{status}");
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains(human_message), "{expected}: {stdout}");
                assert!(
                    stdout.contains(
                        "1 unwrapped toolchain(s) can still build locally via absolute path"
                    ),
                    "{expected}: {stdout}"
                );
                assert!(stdout.contains("rch shim install"), "{stdout}");
                if expected != "none" {
                    assert!(
                        !stdout.contains("cargo is not being intercepted"),
                        "{stdout}"
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn dispatcher_local_build_warning_reaches_status_doctor_and_watch_without_daemon() {
    use std::io::{BufReader, Read, Write};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    struct HeldChild(Child);
    impl Drop for HeldChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"),
        "[general]\nrole = \"dispatcher\"\n[self_healing]\nhook_starts_daemon = false\ndaemon_installs_hooks = false\n").unwrap();
    std::fs::write(config_dir.join("workers.toml"), "workers = []\n").unwrap();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let spawn_cargo = |managed: bool| {
        let cargo_home = temp.path().join(if managed {
            "cargo-managed"
        } else {
            "cargo-unmanaged"
        });
        std::fs::create_dir_all(&cargo_home).unwrap();
        let mut command = Command::new(&cargo);
        command
            .arg("login")
            .env("CARGO_HOME", cargo_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if managed {
            command
                .env("RCH_CARGO_WRAPPER_BYPASS", "1")
                .env("RCH_CARGO_WRAPPER_ORIGIN", "rch");
        } else {
            command
                .env_remove("RCH_CARGO_WRAPPER_BYPASS")
                .env_remove("RCH_CARGO_WRAPPER_ORIGIN");
        }
        let mut child = HeldChild(command.spawn().expect("spawn real cargo login"));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "cargo login exited before observation"
            );
            let comm =
                std::fs::read_to_string(format!("/proc/{}/comm", child.0.id())).unwrap_or_default();
            if matches!(comm.trim(), "cargo" | "cargo-rch-real") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cargo never became observable: {comm:?}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        child
    };
    let unmanaged = spawn_cargo(false);
    let managed = spawn_cargo(true);
    let unmanaged_pid = format!("pid={} ", unmanaged.0.id());
    let managed_pid = format!("pid={} ", managed.0.id());
    let cli = |machine: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch"));
        command
            .current_dir(temp.path())
            .env("HOME", temp.path())
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("XDG_CONFIG_HOME", temp.path().join("xdg-config"))
            .env("RCH_CONFIG_DIR", &config_dir)
            .env("RCH_SOCKET_PATH", temp.path().join("absent.sock"))
            .env("RCH_LOG_LEVEL", "warn")
            .env_remove("RUST_LOG")
            .env_remove("RCH_LOG_FILE")
            .env_remove("RCH_DAEMON_SOCKET")
            .env_remove("RCH_JSON")
            .env_remove("RCH_OUTPUT_FORMAT")
            .env_remove("TOON_DEFAULT_FORMAT")
            .arg("--no-self-healing");
        if machine {
            command.args(["--json", "--format=json"]);
        }
        command
    };
    let assert_attribution = |detail: &str| {
        assert!(
            detail.contains(&unmanaged_pid),
            "missing unmanaged PID: {detail}"
        );
        assert!(
            !detail.contains(&managed_pid),
            "managed PID was reported: {detail}"
        );
    };

    let human = cli(false).arg("status").output().unwrap();
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert_attribution(&stderr);
    assert_eq!(
        stderr.matches("RCH LOCAL BUILD ALARM:").count(),
        1,
        "{stderr}"
    );
    for args in [
        vec!["status"],
        vec!["status", "--fleet"],
        vec!["status", "--remediation"],
    ] {
        let output = cli(true).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("RCH LOCAL BUILD ALARM:"), "{stderr}");
        assert!(
            !output.status.success(),
            "missing daemon must retain failure status"
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let warning = value["error"]["context"]["local_build_warning"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "{args:?} omitted local_build_warning: exit={} JSON={value} stderr={stderr}",
                    output.status
                )
            });
        assert_attribution(warning);
    }
    // A reachable service with a malformed response must preserve the same
    // warning. These sockets test protocol errors, not a healthy real daemon.
    for (index, body) in ["not-json", "{\"daemon\":"].into_iter().enumerate() {
        let socket = temp.path().join(format!("invalid-{index}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 12];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"GET /status\n");
            write!(stream, "HTTP/1.1 200 OK\r\n\r\n{body}").unwrap();
        });
        let output = cli(true)
            .env("RCH_SOCKET_PATH", socket)
            .arg("status")
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(!output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_attribution(
            value["error"]["context"]["local_build_warning"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "malformed daemon body {body:?} omitted local_build_warning: JSON={value} stderr={}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                }),
        );
    }
    for args in [
        vec!["doctor"],
        vec!["doctor", "--reliability", "--scope=triage"],
    ] {
        let output = cli(true).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("RCH LOCAL BUILD ALARM:"), "{stderr}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let collection = if args.len() == 1 {
            "checks"
        } else {
            "diagnostics"
        };
        let check = value["data"][collection]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| {
                check["name"] == "dispatcher_local_builds"
                    || check["check_name"] == "dispatcher_local_builds"
            })
            .expect("public doctor path must include local-build diagnostic");
        assert_attribution(check["details"].as_str().unwrap());
    }

    let mut watch = HeldChild(
        cli(true)
            .args([
                "doctor",
                "--reliability",
                "--scope=triage",
                "--watch",
                "--watch-interval=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = watch.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for value in serde_json::Deserializer::from_reader(BufReader::new(stdout))
            .into_iter::<serde_json::Value>()
        {
            if sender.send(value).is_err() {
                break;
            }
        }
    });
    for expected_sweep in [1, 2] {
        let value = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("watch sweep")
            .unwrap();
        assert_eq!(value["sweep_index"].as_u64(), Some(expected_sweep));
        let check = value["response"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["check_name"] == "dispatcher_local_builds")
            .unwrap();
        assert_attribution(check["details"].as_str().unwrap());
    }
    drop(watch);
    reader.join().unwrap();

    // Worker role must not report this dispatcher-only condition, even while
    // the very same unmanaged Cargo process remains alive.
    std::fs::write(
        config_dir.join("config.toml"),
        "[general]\nrole = \"worker\"\n",
    )
    .unwrap();
    let output = cli(true)
        .args(["doctor", "--reliability", "--scope=triage"])
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !value["data"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["check_name"] == "dispatcher_local_builds")
    );
}

// =============================================================================
// Fleet GC Failure-Path Tests
// =============================================================================

#[cfg(target_os = "linux")]
#[test]
fn gc_timeout_streams_progress_reaps_ssh_and_emits_one_machine_response() {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    struct GcChild(Child);
    impl Drop for GcChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // This executable is an explicit protocol/transport fixture. It does not
    // contact an SSH server or execute a collection command on any worker.
    // Apply-mode replies are synthetic metrics, not evidence of real removal.
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let config = temp.path().join("config");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let ssh = bin.join("ssh");
    std::fs::write(
        &ssh,
        "#!/bin/sh\n\
         for arg do\n\
           case \"$arg\" in\n\
             *fixture-slow*)\n\
               if [ \"$RCH_GC_FIXTURE_APPLY\" = 1 ]; then\n\
                 case \"$*\" in\n\
                   *RCH_TARGET_ENTRY*)\n\
                     printf 'RCH_GC_ROOT resolved /tmp\\nRCH_GC_ROOT tmp /tmp\\nRCH_GC_GATES handles=1 handles_source=proc procs=1\\n'\n\
                     i=0\n\
                     while [ \"$i\" -le 100 ]; do\n\
                       printf 'RCH_TARGET_ENTRY 1 10 free free /tmp/rch_target_fixture_%s\\n' \"$i\"\n\
                       i=$((i + 1))\n\
                     done\n\
                     exit 0\n\
                     ;;\n\
                 esac\n\
                 if [ ! -e \"$RCH_GC_FIXTURE_BATCH\" ]; then\n\
                   printf 'completed\\n' > \"$RCH_GC_FIXTURE_BATCH\"\n\
                   i=0\n\
                   while [ \"$i\" -lt 100 ]; do\n\
                     printf 'RCH_REAP_RM 10 ttl /tmp/rch_target_fixture_%s\\n' \"$i\"\n\
                     i=$((i + 1))\n\
                   done\n\
                   printf 'RCH_WORKER_REAP_METRICS removed=100 freed_kb=1000\\n'\n\
                   exit 0\n\
                 fi\n\
               fi\n\
               printf '%s\\n' \"$$\" > \"$RCH_GC_FIXTURE_PID_FILE\"\n\
               exec /bin/sleep 6\n\
               ;;\n\
           esac\n\
         done\n\
         printf 'controlled SSH connection failure\\n' >&2\n\
         exit 255\n",
    )
    .unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        config.join("config.toml"),
        "[self_healing]\nhook_starts_daemon = false\ndaemon_installs_hooks = false\n",
    )
    .unwrap();
    std::fs::write(
        config.join("workers.toml"),
        "[[workers]]\nid = \"slow\"\nhost = \"fixture-slow.invalid\"\nuser = \"fixture\"\nidentity_file = \"missing\"\n\
         [[workers]]\nid = \"fast\"\nhost = \"fixture-fast.invalid\"\nuser = \"fixture\"\nidentity_file = \"missing\"\n",
    )
    .unwrap();
    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();

    for (format, apply) in [
        ("json", false),
        ("toon", false),
        ("json", true),
        ("toon", true),
    ] {
        let pid_file = temp.path().join(format!("ssh-{format}-{apply}.pid"));
        let batch_file = temp.path().join(format!("batch-{format}-{apply}"));
        let mut child = GcChild(
            Command::new(env!("CARGO_BIN_EXE_rch"))
                .current_dir(temp.path())
                .env("HOME", temp.path())
                .env("XDG_CACHE_HOME", temp.path().join("cache"))
                .env("XDG_CONFIG_HOME", temp.path().join("xdg-config"))
                .env("RCH_CONFIG_DIR", &config)
                .env("RCH_GC_FIXTURE_PID_FILE", &pid_file)
                .env("RCH_GC_FIXTURE_APPLY", if apply { "1" } else { "0" })
                .env("RCH_GC_FIXTURE_BATCH", batch_file)
                .env("PATH", &path)
                .env("NO_COLOR", "1")
                .env("RCH_LOG_LEVEL", "error")
                .env_remove("RUST_LOG")
                .env_remove("RCH_LOG_FILE")
                .env_remove("RCH_JSON")
                .env_remove("RCH_OUTPUT_FORMAT")
                .env_remove("TOON_DEFAULT_FORMAT")
                .args([
                    "--no-self-healing",
                    "--json",
                    &format!("--format={format}"),
                    "gc",
                    "--worker-timeout=2",
                ])
                .args(apply.then_some("--apply"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let stdout_reader = std::thread::spawn(move || {
            let mut text = String::new();
            BufReader::new(stdout).read_to_string(&mut text).unwrap();
            text
        });
        let stderr = child.0.stderr.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let stderr_reader = std::thread::spawn(move || {
            let mut text = String::new();
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                let _ = sender.send(line.clone());
                text.push_str(&line);
                text.push('\n');
            }
            text
        });

        let deadline = Instant::now() + Duration::from_secs(12);
        let mut fast_finished_while_running = false;
        while let Ok(line) = receiver.recv_timeout(Duration::from_secs(10)) {
            if line.starts_with("[rch gc] fast: failed:") {
                fast_finished_while_running = child.0.try_wait().unwrap().is_none();
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(child); // Always clean up the CLI before assertions, even on failure.
        let stdout = stdout_reader.join().unwrap();
        let stderr = stderr_reader.join().unwrap();

        let pid = std::fs::read_to_string(&pid_file)
            .unwrap_or_else(|error| {
                panic!(
                    "slow SSH fixture missing ({format}, apply={apply}): {error}; status={status:?}; stdout={stdout}; stderr={stderr}"
                )
            })
            .trim()
            .parse::<u32>()
            .unwrap();
        let process_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        let ssh_was_reaped = !process_path.exists();
        // A broken runner may leave our six-second fixture alive. Let that
        // bounded fixture finish before reporting failure; never kill by a
        // potentially reused PID or leave an indefinite sleeper behind.
        let cleanup_deadline = Instant::now() + Duration::from_secs(7);
        while !ssh_was_reaped && process_path.exists() && Instant::now() < cleanup_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }

        assert!(status.is_some(), "GC exceeded its watchdog: {stderr}");
        assert_eq!(status.unwrap().code(), Some(1), "{stderr}");
        assert!(fast_finished_while_running, "buffered progress: {stderr}");
        let fast = stderr.find("[rch gc] fast: failed:").unwrap();
        let slow = stderr.find("[rch gc] slow: timed out:").unwrap();
        assert!(fast < slow, "slow worker blocked fast worker: {stderr}");
        assert!(ssh_was_reaped, "GC returned with SSH PID {pid} still alive");

        let json = if format == "toon" {
            toon_rust::toon_to_json(&stdout).unwrap()
        } else {
            stdout.clone()
        };
        // from_str rejects a second trailing response document.
        let value: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("invalid {format} response: {error}: {stdout}"));
        assert_eq!(value["success"], false);
        assert_eq!(value["command"], "gc");
        assert_eq!(value["error"]["code"], "RCH-E104");
        assert_eq!(value["data"]["dry_run"], !apply);
        assert_eq!(value["data"]["applied"], apply);
        let workers = value["data"]["workers"].as_array().unwrap();
        assert_eq!(workers.len(), 2);
        let slow = workers.iter().find(|row| row["id"] == "slow").unwrap();
        let fast = workers.iter().find(|row| row["id"] == "fast").unwrap();
        assert_eq!(slow["timed_out"], true);
        assert_eq!(slow["apply_outcome_unknown"], apply);
        assert_eq!(slow["phase"], if apply { "collect" } else { "enumerate" });
        if apply {
            // These are confirmed replies from batch one. Batch two must not
            // erase them or claim its own unknown result as zero removals.
            assert_eq!(slow["removed"].as_f64(), Some(100.0));
            assert_eq!(slow["freed_kb"].as_f64(), Some(1000.0));
            assert_eq!(slow["entries"].as_array().unwrap().len(), 100);
            assert_eq!(
                slow["unknown_batch_paths"],
                serde_json::json!(["/tmp/rch_target_fixture_100"])
            );
            assert!(stderr.contains("unknown"), "{stderr}");
            assert!(stderr.contains("100 confirmed"), "{stderr}");
        }
        assert_eq!(fast["timed_out"], false);
        assert_eq!(fast["ok"], false);
    }
}

// =============================================================================
// Help and Version Tests
// =============================================================================

#[test]
fn test_rch_help_includes_description() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_help_includes_description");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--help")
        .output()
        .expect("Failed to run rch --help");

    assert!(output.status.success(), "rch --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "Remote Compilation Helper");
    crate::test_log!("TEST PASS: test_rch_help_includes_description");
}

#[test]
fn test_rch_version_output() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_version_output");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--version")
        .output()
        .expect("Failed to run rch --version");

    assert!(output.status.success(), "rch --version failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Version string should contain "rch" and a version number pattern
    assert_contains(&stdout, "rch");
    crate::test_log!("Version output: {}", stdout.trim());
    crate::test_log!("TEST PASS: test_rch_version_output");
}

#[test]
fn test_exec_refuses_non_compilation_local_fallback_when_remote_required() {
    init_test_logging();
    crate::test_log!(
        "TEST START: test_exec_refuses_non_compilation_local_fallback_when_remote_required"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_REQUIRE_REMOTE", "1")
        .args(["exec", "--", "echo", "should_not_run_locally"])
        .output()
        .expect("Failed to run rch exec non-compilation command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "RCH_REQUIRE_REMOTE=1 must fail closed for non-compilation exec commands"
    );
    assert!(
        stdout.trim().is_empty(),
        "non-compilation command must not execute locally; stdout={stdout:?}"
    );
    assert_contains(
        &stderr,
        "remote required; refusing local fallback [RCH-E301] (non-compilation command)",
    );

    crate::test_log!(
        "TEST PASS: test_exec_refuses_non_compilation_local_fallback_when_remote_required"
    );
}

#[test]
fn test_exec_refuses_shell_wrapped_cargo_without_local_fallback() {
    init_test_logging();
    crate::test_log!("TEST START: test_exec_refuses_shell_wrapped_cargo_without_local_fallback");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["exec", "--", "sh", "-c", "cargo build --release"])
        .output()
        .expect("Failed to run rch exec shell-wrapped cargo command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "shell-wrapped cargo must fail before either remote execution or local fallback"
    );
    assert!(stdout.trim().is_empty(), "stdout={stdout:?}");
    assert_contains(&stderr, "[RCH-E301] refusing shell-wrapped cargo command");
    assert_contains(&stderr, "invoke `rch exec -- cargo ...` directly");

    crate::test_log!("TEST PASS: test_exec_refuses_shell_wrapped_cargo_without_local_fallback");
}

// =============================================================================
// Subcommand Help Tests
// =============================================================================

#[test]
fn test_daemon_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "--help"])
        .output()
        .expect("Failed to run rch daemon --help");

    assert!(output.status.success(), "rch daemon --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "daemon");
    crate::test_log!("TEST PASS: test_daemon_subcommand_help");
}

#[test]
fn test_workers_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "--help"])
        .output()
        .expect("Failed to run rch workers --help");

    assert!(output.status.success(), "rch workers --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "workers");
    crate::test_log!("TEST PASS: test_workers_subcommand_help");
}

#[test]
fn test_config_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "--help"])
        .output()
        .expect("Failed to run rch config --help");

    assert!(output.status.success(), "rch config --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "config");
    crate::test_log!("TEST PASS: test_config_subcommand_help");
}

#[test]
fn test_hook_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "--help"])
        .output()
        .expect("Failed to run rch hook --help");

    assert!(output.status.success(), "rch hook --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "hook");
    crate::test_log!("TEST PASS: test_hook_subcommand_help");
}

#[test]
fn test_status_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_status_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["status", "--help"])
        .output()
        .expect("Failed to run rch status --help");

    assert!(output.status.success(), "rch status --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "status");
    crate::test_log!("TEST PASS: test_status_subcommand_help");
}

#[test]
fn test_diagnose_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "--help"])
        .output()
        .expect("Failed to run rch diagnose --help");

    assert!(output.status.success(), "rch diagnose --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "diagnose");
    crate::test_log!("TEST PASS: test_diagnose_subcommand_help");
}

#[test]
fn test_doctor_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_doctor_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["doctor", "--help"])
        .output()
        .expect("Failed to run rch doctor --help");

    assert!(output.status.success(), "rch doctor --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "doctor");
    assert_contains(&stdout, "--reliability");
    assert_contains(&stdout, "--check-schemas");
    crate::test_log!("TEST PASS: test_doctor_subcommand_help");
}

#[test]
fn test_doctor_reliability_json_outputs_real_binary_response() {
    init_test_logging();
    crate::test_log!("TEST START: test_doctor_reliability_json_outputs_real_binary_response");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["doctor", "--reliability", "--check-schemas", "--json"])
        .output()
        .expect("Failed to run rch doctor --reliability --check-schemas --json");

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("reliability doctor should output JSON");
    assert_eq!(
        parsed.pointer("/success").and_then(|value| value.as_bool()),
        Some(true)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let overall = parsed
        .pointer("/data/summary/overall")
        .and_then(|value| value.as_str())
        .expect("reliability doctor should report an overall verdict");
    let expected_exit = match overall {
        "healthy" => Some(0),
        "degraded" => Some(1),
        "failing" => Some(2),
        _ => None,
    };
    assert!(
        expected_exit.is_some(),
        "unexpected reliability verdict: {overall}"
    );
    assert_eq!(
        output.status.code(),
        expected_exit,
        "rch doctor --reliability should use the documented exit code for verdict {overall}; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    assert_eq!(
        parsed
            .pointer("/data/schema_version")
            .and_then(|value| value.as_str()),
        Some("1.1.0")
    );
    assert_eq!(
        parsed
            .pointer("/data/mode")
            .and_then(|value| value.as_str()),
        Some("check")
    );

    let diagnostics = parsed
        .pointer("/data/diagnostics")
        .and_then(|value| value.as_array())
        .expect("reliability doctor data should include diagnostics");
    assert!(
        !diagnostics.is_empty(),
        "reliability doctor should report at least one diagnostic"
    );
    assert!(
        parsed
            .pointer("/data/remediation_plan")
            .and_then(|value| value.as_array())
            .is_some(),
        "reliability doctor data should include remediation_plan"
    );

    let categories = diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.get("category").and_then(|value| value.as_str()))
        .collect::<Vec<_>>();
    for expected in [
        "topology",
        "repo_presence",
        "disk_pressure",
        "process_debt",
        "helper_compatibility",
        "rollout_posture",
        "schema_compatibility",
    ] {
        assert!(
            categories.contains(&expected),
            "missing reliability category {expected}; categories={categories:?}"
        );
    }

    crate::test_log!("TEST PASS: test_doctor_reliability_json_outputs_real_binary_response");
}

#[test]
fn test_doctor_handles_closed_stdout_pipe() {
    init_test_logging();
    crate::test_log!("TEST START: test_doctor_handles_closed_stdout_pipe");

    let output = Command::new("bash")
        .args([
            "-o",
            "pipefail",
            "-c",
            "\"$RCH_BIN\" doctor 2>&1 | head -20",
        ])
        .env("RCH_BIN", env!("CARGO_BIN_EXE_rch"))
        .output()
        .expect("Failed to run rch doctor pipe regression");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rch doctor should exit cleanly when stdout closes early; status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert_contains(&stdout, "RCH Diagnostic Report");
    assert!(
        !stderr.contains("panicked") && !stderr.contains("core dumped"),
        "rch doctor should not report a panic or abort when piped to head; stderr:\n{stderr}"
    );
    crate::test_log!("TEST PASS: test_doctor_handles_closed_stdout_pipe");
}

#[test]
fn test_speedscore_subcommand_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_speedscore_subcommand_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["speedscore", "--help"])
        .output()
        .expect("Failed to run rch speedscore --help");

    assert!(output.status.success(), "rch speedscore --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_contains(&stdout, "speedscore");
    crate::test_log!("TEST PASS: test_speedscore_subcommand_help");
}

// =============================================================================
// Invalid Command Tests
// =============================================================================

#[test]
fn test_invalid_subcommand_fails() {
    init_test_logging();
    crate::test_log!("TEST START: test_invalid_subcommand_fails");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("nonexistent-command")
        .output()
        .expect("Failed to run rch nonexistent-command");

    assert!(
        !output.status.success(),
        "Expected failure for invalid subcommand"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain error message about unrecognized command
    assert!(
        stderr.contains("error") || stderr.contains("unrecognized"),
        "Expected error message in stderr: {}",
        stderr
    );
    crate::test_log!("TEST PASS: test_invalid_subcommand_fails");
}

#[test]
fn test_invalid_flag_fails() {
    init_test_logging();
    crate::test_log!("TEST START: test_invalid_flag_fails");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--nonexistent-flag")
        .output()
        .expect("Failed to run rch --nonexistent-flag");

    assert!(
        !output.status.success(),
        "Expected failure for invalid flag"
    );
    crate::test_log!("TEST PASS: test_invalid_flag_fails");
}

// =============================================================================
// Global Flag Tests
// =============================================================================

#[test]
fn test_global_verbose_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_verbose_flag_accepted");

    // --verbose should be accepted with --help (doesn't actually run command)
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--verbose", "--help"])
        .output()
        .expect("Failed to run rch --verbose --help");

    assert!(output.status.success(), "rch --verbose --help failed");
    crate::test_log!("TEST PASS: test_global_verbose_flag_accepted");
}

#[test]
fn test_global_quiet_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_quiet_flag_accepted");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--quiet", "--help"])
        .output()
        .expect("Failed to run rch --quiet --help");

    assert!(output.status.success(), "rch --quiet --help failed");
    crate::test_log!("TEST PASS: test_global_quiet_flag_accepted");
}

#[test]
fn test_global_json_flag_accepted() {
    init_test_logging();
    crate::test_log!("TEST START: test_global_json_flag_accepted");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--json", "--help"])
        .output()
        .expect("Failed to run rch --json --help");

    assert!(output.status.success(), "rch --json --help failed");
    crate::test_log!("TEST PASS: test_global_json_flag_accepted");
}

#[test]
fn test_global_color_flag_accepted() -> Result<(), Box<dyn std::error::Error>> {
    init_test_logging();
    crate::test_log!("TEST START: test_global_color_flag_accepted");

    for mode in ["auto", "always", "never"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rch"))
            .args(["--color", mode, "--help"])
            .output()?;

        assert!(
            output.status.success(),
            "rch --color {} --help failed",
            mode
        );
    }
    crate::test_log!("TEST PASS: test_global_color_flag_accepted");
    Ok(())
}

#[test]
fn test_global_format_flag_accepted() -> Result<(), Box<dyn std::error::Error>> {
    init_test_logging();
    crate::test_log!("TEST START: test_global_format_flag_accepted");

    for format in ["json", "toon"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rch"))
            .args(["--format", format, "--help"])
            .output()?;

        assert!(
            output.status.success(),
            "rch --format {} --help failed",
            format
        );
    }
    crate::test_log!("TEST PASS: test_global_format_flag_accepted");
    Ok(())
}

// =============================================================================
// Diagnose Command Tests
// =============================================================================

#[test]
fn test_diagnose_cargo_build_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_cargo_build_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "cargo", "build", "--release"])
        .output()
        .expect("Failed to run rch diagnose cargo build --release");

    // Command should succeed (even without daemon running, it can classify)
    // It may fail if daemon is not running, but parsing should work
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    // The command should at least attempt to classify
    crate::test_log!("TEST PASS: test_diagnose_cargo_build_command");
}

#[test]
fn test_diagnose_quoted_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_quoted_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "cargo build --release"])
        .output()
        .expect("Failed to run rch diagnose 'cargo build --release'");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    crate::test_log!("TEST PASS: test_diagnose_quoted_command");
}

#[test]
fn test_diagnose_non_compilation_command() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_non_compilation_command");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["diagnose", "ls", "-la"])
        .output()
        .expect("Failed to run rch diagnose ls -la");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    crate::test_log!("stdout: {}", stdout);
    crate::test_log!("stderr: {}", stderr);

    crate::test_log!("TEST PASS: test_diagnose_non_compilation_command");
}

#[test]
fn test_diagnose_json_output() {
    init_test_logging();
    crate::test_log!("TEST START: test_diagnose_json_output");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--json", "diagnose", "cargo", "build"])
        .output()
        .expect("Failed to run rch --json diagnose cargo build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    crate::test_log!("JSON output: {}", stdout);

    // If output is non-empty, it should be valid JSON structure
    if !stdout.trim().is_empty() {
        // Basic check that it looks like JSON (starts with { or [)
        let trimmed = stdout.trim();
        assert!(
            trimmed.starts_with('{') || trimmed.starts_with('['),
            "Expected JSON output to start with {{ or [, got: {}",
            &trimmed[..trimmed.len().min(100)]
        );
    }

    crate::test_log!("TEST PASS: test_diagnose_json_output");
}

// =============================================================================
// Workers Subcommand Tests
// =============================================================================

#[test]
fn test_workers_list_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_list_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "list", "--help"])
        .output()
        .expect("Failed to run rch workers list --help");

    assert!(output.status.success(), "rch workers list --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "list");
    crate::test_log!("TEST PASS: test_workers_list_help");
}

#[test]
fn test_workers_probe_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_probe_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "probe", "--help"])
        .output()
        .expect("Failed to run rch workers probe --help");

    assert!(output.status.success(), "rch workers probe --help failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "probe");
    crate::test_log!("TEST PASS: test_workers_probe_help");
}

#[test]
fn test_workers_capabilities_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_workers_capabilities_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["workers", "capabilities", "--help"])
        .output()
        .expect("Failed to run rch workers capabilities --help");

    assert!(
        output.status.success(),
        "rch workers capabilities --help failed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "capabilities");
    crate::test_log!("TEST PASS: test_workers_capabilities_help");
}

// =============================================================================
// Daemon Subcommand Tests
// =============================================================================

#[test]
fn test_daemon_start_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_start_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "start", "--help"])
        .output()
        .expect("Failed to run rch daemon start --help");

    assert!(output.status.success(), "rch daemon start --help failed");
    crate::test_log!("TEST PASS: test_daemon_start_help");
}

#[test]
fn test_daemon_status_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_daemon_status_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["daemon", "status", "--help"])
        .output()
        .expect("Failed to run rch daemon status --help");

    assert!(output.status.success(), "rch daemon status --help failed");
    crate::test_log!("TEST PASS: test_daemon_status_help");
}

// =============================================================================
// Config Subcommand Tests
// =============================================================================

#[test]
fn test_config_show_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_show_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "show", "--help"])
        .output()
        .expect("Failed to run rch config show --help");

    assert!(output.status.success(), "rch config show --help failed");
    crate::test_log!("TEST PASS: test_config_show_help");
}

#[test]
fn test_config_validate_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_config_validate_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["config", "validate", "--help"])
        .output()
        .expect("Failed to run rch config validate --help");

    assert!(output.status.success(), "rch config validate --help failed");
    crate::test_log!("TEST PASS: test_config_validate_help");
}

// =============================================================================
// Error Catalog Command Tests
// =============================================================================

#[test]
fn test_error_list_unknown_category_fails() {
    init_test_logging();
    crate::test_log!("TEST START: test_error_list_unknown_category_fails");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["error", "list", "--category", "nonexistent_category"])
        .output()
        .expect("Failed to run rch error list");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown category should be a usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains(&stderr, "Unknown error category");
    assert_contains(&stderr, "disk_pressure");
    crate::test_log!("TEST PASS: test_error_list_unknown_category_fails");
}

#[test]
fn test_error_list_unknown_category_json_fails_with_remediation() {
    init_test_logging();
    crate::test_log!("TEST START: test_error_list_unknown_category_json_fails_with_remediation");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args([
            "error",
            "list",
            "--category",
            "nonexistent_category",
            "--json",
        ])
        .output()
        .expect("Failed to run rch error list --json");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown category should be a usage error"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "\"success\": false");
    assert_contains(&stdout, "\"known_categories\"");
    assert_contains(&stdout, "nonexistent_category");
    crate::test_log!("TEST PASS: test_error_list_unknown_category_json_fails_with_remediation");
}

// =============================================================================
// Hook Subcommand Tests
// =============================================================================

#[test]
fn test_hook_install_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_install_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "install", "--help"])
        .output()
        .expect("Failed to run rch hook install --help");

    assert!(output.status.success(), "rch hook install --help failed");
    crate::test_log!("TEST PASS: test_hook_install_help");
}

#[test]
fn test_hook_uninstall_help() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_uninstall_help");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["hook", "uninstall", "--help"])
        .output()
        .expect("Failed to run rch hook uninstall --help");

    assert!(output.status.success(), "rch hook uninstall --help failed");
    crate::test_log!("TEST PASS: test_hook_uninstall_help");
}

// =============================================================================
// Short Alias Tests
// =============================================================================

#[test]
fn test_short_verbose_flag() {
    init_test_logging();
    crate::test_log!("TEST START: test_short_verbose_flag");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["-v", "--help"])
        .output()
        .expect("Failed to run rch -v --help");

    assert!(output.status.success(), "rch -v --help failed");
    crate::test_log!("TEST PASS: test_short_verbose_flag");
}

#[test]
fn test_short_quiet_flag() {
    init_test_logging();
    crate::test_log!("TEST START: test_short_quiet_flag");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["-q", "--help"])
        .output()
        .expect("Failed to run rch -q --help");

    assert!(output.status.success(), "rch -q --help failed");
    crate::test_log!("TEST PASS: test_short_quiet_flag");
}

// =============================================================================
// Environment Variable Tests
// =============================================================================

#[test]
fn test_rch_verbose_env_var() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_verbose_env_var");

    // RCH_VERBOSE environment variable should be respected
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_VERBOSE", "true")
        .arg("--help")
        .output()
        .expect("Failed to run rch with RCH_VERBOSE=true");

    assert!(
        output.status.success(),
        "rch with RCH_VERBOSE=true --help failed"
    );
    crate::test_log!("TEST PASS: test_rch_verbose_env_var");
}

#[test]
fn test_rch_output_format_env_var() {
    init_test_logging();
    crate::test_log!("TEST START: test_rch_output_format_env_var");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_OUTPUT_FORMAT", "json")
        .arg("--help")
        .output()
        .expect("Failed to run rch with RCH_OUTPUT_FORMAT=json");

    assert!(
        output.status.success(),
        "rch with RCH_OUTPUT_FORMAT=json --help failed"
    );
    crate::test_log!("TEST PASS: test_rch_output_format_env_var");
}

// =============================================================================
// Machine Discovery Flags Tests (--help-json, --capabilities)
// =============================================================================

#[test]
fn test_help_json_outputs_valid_json() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_outputs_valid_json");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--help-json")
        .output()
        .expect("Failed to run rch --help-json");

    assert!(output.status.success(), "rch --help-json failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json should output valid JSON");

    // Should have expected structure
    assert!(parsed.get("name").is_some(), "Missing 'name' field");
    assert!(
        parsed.get("subcommands").is_some(),
        "Missing 'subcommands' field"
    );
    assert!(parsed.get("version").is_some(), "Missing 'version' field");

    crate::test_log!("TEST PASS: test_help_json_outputs_valid_json");
}

#[test]
fn test_help_json_with_subcommand() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_with_subcommand");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--help-json", "workers"])
        .output()
        .expect("Failed to run rch --help-json workers");

    assert!(output.status.success(), "rch --help-json workers failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json workers should output valid JSON");

    // Should be for the workers subcommand
    assert_eq!(
        parsed.get("name").and_then(|v| v.as_str()),
        Some("workers"),
        "Should be 'workers' subcommand"
    );

    // Should have nested subcommands
    let subcommands = parsed.get("subcommands").and_then(|v| v.as_array());
    assert!(subcommands.is_some(), "workers should have subcommands");
    assert!(
        !subcommands.unwrap().is_empty(),
        "workers should have subcommands"
    );

    crate::test_log!("TEST PASS: test_help_json_with_subcommand");
}

#[test]
fn test_help_json_nested_subcommand_includes_arguments() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_nested_subcommand_includes_arguments");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--help-json", "workers/list"])
        .output()
        .expect("Failed to run rch --help-json workers/list");

    assert!(
        output.status.success(),
        "rch --help-json workers/list failed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json workers/list should output valid JSON");

    assert_eq!(
        parsed.get("name").and_then(|v| v.as_str()),
        Some("list"),
        "Should be the workers list subcommand"
    );

    let arg_names: Vec<&str> = parsed
        .get("arguments")
        .and_then(|v| v.as_array())
        .expect("nested help should include an arguments array")
        .iter()
        .filter_map(|arg| arg.get("name").and_then(|v| v.as_str()))
        .collect();

    assert!(
        arg_names.contains(&"speedscore"),
        "workers/list help-json should expose the --speedscore flag"
    );

    crate::test_log!("TEST PASS: test_help_json_nested_subcommand_includes_arguments");
}

#[test]
fn test_help_json_space_separated_nested_subcommand_path() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_space_separated_nested_subcommand_path");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--help-json", "workers", "list"])
        .output()
        .expect("Failed to run rch --help-json workers list");

    assert!(
        output.status.success(),
        "rch --help-json workers list failed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json workers list should output valid JSON");

    assert_eq!(parsed.get("name").and_then(|v| v.as_str()), Some("list"));

    crate::test_log!("TEST PASS: test_help_json_space_separated_nested_subcommand_path");
}

#[test]
fn test_help_json_resolves_subcommand_alias() {
    init_test_logging();
    crate::test_log!("TEST START: test_help_json_resolves_subcommand_alias");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--help-json", "tui"])
        .output()
        .expect("Failed to run rch --help-json tui");

    assert!(output.status.success(), "rch --help-json tui failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--help-json tui should output valid JSON");

    assert_eq!(
        parsed.get("name").and_then(|v| v.as_str()),
        Some("dashboard")
    );

    crate::test_log!("TEST PASS: test_help_json_resolves_subcommand_alias");
}

#[test]
fn test_capabilities_outputs_valid_json() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_outputs_valid_json");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--capabilities should output valid JSON");

    // Should have expected structure
    assert!(parsed.get("version").is_some(), "Missing 'version' field");
    assert!(parsed.get("runtimes").is_some(), "Missing 'runtimes' field");
    assert!(parsed.get("commands").is_some(), "Missing 'commands' field");
    assert!(parsed.get("features").is_some(), "Missing 'features' field");

    crate::test_log!("TEST PASS: test_capabilities_outputs_valid_json");
}

#[test]
fn test_capabilities_lists_supported_runtimes() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_lists_supported_runtimes");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let runtimes = parsed.get("runtimes").and_then(|v| v.as_array()).unwrap();

    // Should list rust, bun, and node runtimes
    let runtime_names: Vec<&str> = runtimes
        .iter()
        .filter_map(|r| r.get("name").and_then(|n| n.as_str()))
        .collect();

    assert!(
        runtime_names.contains(&"rust"),
        "Should support rust runtime"
    );
    assert!(runtime_names.contains(&"bun"), "Should support bun runtime");
    assert!(
        runtime_names.contains(&"node"),
        "Should support node runtime"
    );

    crate::test_log!("TEST PASS: test_capabilities_lists_supported_runtimes");
}

#[test]
fn test_capabilities_lists_all_commands() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_lists_all_commands");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .arg("--capabilities")
        .output()
        .expect("Failed to run rch --capabilities");

    assert!(output.status.success(), "rch --capabilities failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let commands = parsed.get("commands").and_then(|v| v.as_array()).unwrap();

    let command_names: Vec<&str> = commands
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();

    // Verify key commands are listed
    assert!(command_names.contains(&"init"), "Should list init command");
    assert!(
        command_names.contains(&"daemon"),
        "Should list daemon command"
    );
    assert!(
        command_names.contains(&"workers"),
        "Should list workers command"
    );
    assert!(
        command_names.contains(&"status"),
        "Should list status command"
    );
    assert!(
        command_names.contains(&"config"),
        "Should list config command"
    );

    crate::test_log!("TEST PASS: test_capabilities_lists_all_commands");
}

#[test]
fn test_capabilities_command_outputs_api_envelope() {
    init_test_logging();
    crate::test_log!("TEST START: test_capabilities_command_outputs_api_envelope");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["capabilities", "--json"])
        .output()
        .expect("Failed to run rch capabilities --json");

    assert!(output.status.success(), "rch capabilities --json failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("capabilities --json should output valid JSON");

    assert_eq!(parsed.get("success").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        parsed
            .pointer("/data/contract_version")
            .and_then(|v| v.as_str()),
        Some("rch.capabilities.v1")
    );
    assert!(
        parsed
            .pointer("/data/env_vars")
            .and_then(|v| v.as_array())
            .is_some_and(|vars| !vars.is_empty()),
        "capabilities should include env var dictionary"
    );
    assert!(
        parsed
            .pointer("/data/exit_codes")
            .and_then(|v| v.as_array())
            .is_some_and(|codes| !codes.is_empty()),
        "capabilities should include exit code dictionary"
    );

    crate::test_log!("TEST PASS: test_capabilities_command_outputs_api_envelope");
}

#[test]
fn test_robot_docs_guide_outputs_agent_handbook() {
    init_test_logging();
    crate::test_log!("TEST START: test_robot_docs_guide_outputs_agent_handbook");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["robot-docs", "guide"])
        .output()
        .expect("Failed to run rch robot-docs guide");

    assert!(output.status.success(), "rch robot-docs guide failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("RCH Agent Guide"));
    assert!(stdout.contains("rch capabilities --json"));
    assert!(stdout.contains("rch --robot-triage --json"));

    crate::test_log!("TEST PASS: test_robot_docs_guide_outputs_agent_handbook");
}

#[test]
fn test_robot_docs_guide_json_outputs_api_envelope() {
    init_test_logging();
    crate::test_log!("TEST START: test_robot_docs_guide_json_outputs_api_envelope");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["robot-docs", "guide", "--json"])
        .output()
        .expect("Failed to run rch robot-docs guide --json");

    assert!(
        output.status.success(),
        "rch robot-docs guide --json failed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("robot-docs guide --json should be valid JSON");

    assert_eq!(parsed.get("success").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        parsed
            .pointer("/data/contract_version")
            .and_then(|v| v.as_str()),
        Some("rch.robot_docs.v1")
    );
    assert!(
        parsed
            .pointer("/data/guide")
            .and_then(|v| v.as_str())
            .is_some_and(|guide| guide.contains("RCH Agent Guide"))
    );

    crate::test_log!("TEST PASS: test_robot_docs_guide_json_outputs_api_envelope");
}

#[test]
fn test_robot_triage_json_outputs_quick_ref() {
    init_test_logging();
    crate::test_log!("TEST START: test_robot_triage_json_outputs_quick_ref");

    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--robot-triage", "--json"])
        .output()
        .expect("Failed to run rch --robot-triage --json");

    assert!(output.status.success(), "rch --robot-triage --json failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--robot-triage --json should be valid JSON");

    assert_eq!(parsed.get("success").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        parsed
            .pointer("/data/contract_version")
            .and_then(|v| v.as_str()),
        Some("rch.robot_triage.v1")
    );
    assert_eq!(
        parsed
            .pointer("/data/quick_ref/default_probe")
            .and_then(|v| v.as_str()),
        Some("rch check --json")
    );
    assert!(
        parsed
            .pointer("/data/recommended_commands")
            .and_then(|v| v.as_array())
            .is_some_and(|commands| !commands.is_empty())
    );

    crate::test_log!("TEST PASS: test_robot_triage_json_outputs_quick_ref");
}

/// What one isolated `rch --json exec -- cargo check` run did (#114).
#[cfg(unix)]
struct FallbackGateRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    local_cargo_ran: bool,
    incidents: Vec<serde_json::Value>,
}

#[cfg(unix)]
impl FallbackGateRun {
    fn incident(&self, code: &str) -> Option<&serde_json::Value> {
        self.incidents
            .iter()
            .find(|event| event.get("reason_code").and_then(|v| v.as_str()) == Some(code))
    }

    fn envelope(&self) -> serde_json::Value {
        let line = self
            .stdout
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("no exec envelope on stdout; stderr={}", self.stderr));
        serde_json::from_str(line).expect("exec envelope is JSON")
    }
}

/// Run `rch --json exec -- cargo check` against a daemon that is not there.
///
/// Isolation: the environment is cleared, and config, config cache, state,
/// incident ledger, HOME and the daemon socket all live in a temp dir. The
/// socket does not exist and hook autostart is off, so the run can never
/// reach the operator's config or daemon. PATH holds only `sh` and a fake
/// `cargo` that records that it ran on this machine.
///
/// With `resolved_toolchain` the client resolves a Rust toolchain, so the
/// run reaches the daemon socket and takes the daemon-unavailable exit.
/// Without it the project declares no channel and no rustup/rustc is
/// reachable, so the client refuses to request a worker and the run takes the
/// no-admissible-worker exit.
#[cfg(unix)]
fn run_exec_against_absent_daemon(
    allow_local_fallback: bool,
    resolved_toolchain: bool,
    require_remote: bool,
) -> FallbackGateRun {
    run_isolated_exec(
        "",
        allow_local_fallback,
        resolved_toolchain,
        require_remote,
        &["--", "cargo", "check"],
    )
}

/// [`run_exec_against_absent_daemon`] with extra `[general]` config lines and
/// explicit `rch --json exec` arguments (flags, `--`, then the command).
#[cfg(unix)]
fn run_isolated_exec(
    general_extra: &str,
    allow_local_fallback: bool,
    resolved_toolchain: bool,
    require_remote: bool,
    exec_args: &[&str],
) -> FallbackGateRun {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    // The configured root must match the cwd rch observes, including when the
    // temp dir sits behind a symlink (macOS /var -> /private/var).
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let home = root.join("home");
    let config_dir = root.join("config");
    let state_dir = root.join("state");
    let bin = root.join("bin");
    let projects = root.join("projects");
    let project = projects.join("app");
    for dir in [&home, &config_dir, &state_dir, &bin, &project.join("src")] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(project.join("src/lib.rs"), "").unwrap();
    if !resolved_toolchain {
        // A channel-less declaration shadows any rust-toolchain file above the
        // temp dir. Under an offloaded run TMPDIR sits inside the synced
        // checkout, whose own pin would otherwise resolve a toolchain.
        std::fs::write(
            project.join("rust-toolchain.toml"),
            "[toolchain]\ncomponents = [\"rustfmt\"]\n",
        )
        .unwrap();
    }
    let sentinel = root.join("local-cargo-ran");
    let cargo = bin.join("cargo");
    std::fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\n",
            sentinel.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("/bin/sh", bin.join("sh")).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[general]\nsocket_path = \"{socket}\"\n{general_extra}\n\
             [self_healing]\nhook_starts_daemon = false\n\n\
             [compilation]\nallow_local_fallback = {allow_local_fallback}\n\n\
             [path_topology]\ncanonical_root = \"{projects}\"\nalias_root = \"{alias}\"\n",
            socket = root.join("absent-daemon.sock").display(),
            projects = projects.display(),
            alias = root.join("alias").display(),
        ),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_rch"));
    command
        .env_clear()
        .env("PATH", &bin)
        .env("HOME", &home)
        .env("RCH_CONFIG_DIR", &config_dir)
        .env("RCH_STATE_HOME", &state_dir)
        .env("RCH_DISABLE_CONFIG_CACHE", "1")
        .env("RCH_NO_UPDATE_CHECK", "1")
        .env("RCH_RESTART_ADMISSION_WAIT_SECS", "0")
        .current_dir(&project)
        .stdin(std::process::Stdio::null())
        .args(["--json", "exec"])
        .args(exec_args);
    if resolved_toolchain {
        command.env("RUSTUP_TOOLCHAIN", "stable");
    }
    if require_remote {
        command.env("RCH_REQUIRE_REMOTE", "1");
    }
    let output = command.output().expect("run rch exec");
    let incidents = std::fs::read_to_string(state_dir.join("incidents.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("incident ledger line is JSON"))
        .collect();
    FallbackGateRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        local_cargo_ran: sentinel.exists(),
        incidents,
    }
}

#[cfg(unix)]
#[test]
fn exec_allow_local_fallback_false_refuses_every_remote_failure_exit() {
    init_test_logging();
    // #114: `compilation.allow_local_fallback = false` must fail closed, run
    // nothing locally, and leave a refusal (not a fallback) in the ledger.
    for (resolved_toolchain, reason) in [
        (true, "daemon unavailable"),
        (false, "client_toolchain_unresolved"),
    ] {
        let run = run_exec_against_absent_daemon(false, resolved_toolchain, false);
        let context = format!("{reason}: stderr={}", run.stderr);
        assert_eq!(run.status.code(), Some(1), "{context}");
        assert!(!run.local_cargo_ran, "cargo ran locally; {context}");
        assert_contains(
            &run.stderr,
            "[RCH] refusing local fallback (compilation.allow_local_fallback=false; ",
        );
        assert_contains(&run.stderr, reason);
        let envelope = run.envelope();
        assert_eq!(envelope["outcome"], "refused", "{context}");
        assert_eq!(envelope["location"], "local", "{context}");
        let refusal = run
            .incident("RCH-I012")
            .unwrap_or_else(|| panic!("no RCH-I012 refusal incident: {:?}", run.incidents));
        assert_eq!(refusal["local_fallback_allowed"], false, "{context}");
        assert_eq!(
            refusal["details"]["policy"], "compilation.allow_local_fallback=false",
            "{context}"
        );
        assert!(
            run.incident("RCH-I011").is_none(),
            "a local-fallback incident was recorded: {:?}",
            run.incidents
        );
        if resolved_toolchain {
            let socket = run
                .incident("RCH-I010")
                .unwrap_or_else(|| panic!("no RCH-I010 socket incident: {:?}", run.incidents));
            assert_eq!(socket["local_fallback_allowed"], false, "{context}");
        }
    }
}

#[cfg(unix)]
#[test]
fn exec_allow_local_fallback_true_still_falls_back_locally() {
    init_test_logging();
    // Control for the test above: the default fail-open behaviour is intact.
    for resolved_toolchain in [true, false] {
        let run = run_exec_against_absent_daemon(true, resolved_toolchain, false);
        let context = format!(
            "resolved_toolchain={resolved_toolchain}: stderr={}",
            run.stderr
        );
        assert_eq!(run.status.code(), Some(0), "{context}");
        assert!(run.local_cargo_ran, "cargo did not run locally; {context}");
        assert_eq!(run.envelope()["outcome"], "completed", "{context}");
        let fallback = run
            .incident("RCH-I011")
            .unwrap_or_else(|| panic!("no RCH-I011 fallback incident: {:?}", run.incidents));
        assert_eq!(fallback["local_fallback_allowed"], true, "{context}");
    }
}

#[cfg(unix)]
#[test]
fn exec_require_remote_refusal_outranks_allow_local_fallback() {
    init_test_logging();
    // With both gates set, the typed remote-required refusal and its
    // retryable exit code (103) are what callers see.
    for allow_local_fallback in [true, false] {
        let run = run_exec_against_absent_daemon(allow_local_fallback, true, true);
        let context = format!(
            "allow_local_fallback={allow_local_fallback}: stderr={}",
            run.stderr
        );
        assert_eq!(run.status.code(), Some(103), "{context}");
        assert!(!run.local_cargo_ran, "cargo ran locally; {context}");
        assert_contains(&run.stderr, "remote required; refusing local fallback");
        let refusal = run
            .incident("RCH-I012")
            .unwrap_or_else(|| panic!("no RCH-I012 refusal incident: {:?}", run.incidents));
        assert_eq!(refusal["local_fallback_allowed"], false, "{context}");
    }
}

#[cfg(unix)]
#[test]
fn exec_require_remote_flag_refuses_a_non_compilation_command() {
    init_test_logging();
    // #123: `--require-remote` is RCH_REQUIRE_REMOTE=1 for one call. The
    // isolated environment has no RCH_REQUIRE_REMOTE, so the flag alone must
    // turn the silent local run (the control) into the RCH-E301 refusal.
    // The command prints the marker but never spells it, so rch's own log of
    // the command text cannot satisfy or break the checks below.
    let marker = "non-compilation-ran-locally";
    let print_marker = ["printf", "%s-%s\\n", "non-compilation", "ran-locally"];
    let control = run_isolated_exec(
        "",
        true,
        true,
        false,
        &[&["--"][..], &print_marker[..]].concat(),
    );
    let context = format!("control: stderr={}", control.stderr);
    assert_eq!(control.status.code(), Some(0), "{context}");
    assert!(
        control.stdout.contains(marker) || control.stderr.contains(marker),
        "{context}"
    );
    assert_eq!(control.envelope()["outcome"], "completed", "{context}");

    let run = run_isolated_exec(
        "",
        true,
        true,
        false,
        &[&["--require-remote", "--"][..], &print_marker[..]].concat(),
    );
    let context = format!("--require-remote: stderr={}", run.stderr);
    assert_eq!(run.status.code(), Some(1), "{context}");
    assert!(
        !run.stdout.contains(marker) && !run.stderr.contains(marker),
        "the command ran locally; {context}"
    );
    assert_contains(
        &run.stderr,
        "remote required; refusing local fallback [RCH-E301] (non-compilation command)",
    );
    assert_eq!(run.envelope()["outcome"], "refused", "{context}");
    let refusal = run
        .incident("RCH-I012")
        .unwrap_or_else(|| panic!("no RCH-I012 refusal incident: {:?}", run.incidents));
    assert_eq!(refusal["local_fallback_allowed"], false, "{context}");
}

#[cfg(unix)]
#[test]
fn exec_require_remote_flag_outranks_force_local_config() {
    init_test_logging();
    // #123: RCH_REQUIRE_REMOTE=1 yields to an explicit `force_local = true`
    // because the cargo shim exports it into every agent (bd-nfo8f). The flag
    // is always the caller's own request, so like `--worker` it refuses
    // instead of running the build locally.
    let env_only = run_isolated_exec(
        "force_local = true\n",
        true,
        true,
        true,
        &["--", "cargo", "check"],
    );
    let context = format!("RCH_REQUIRE_REMOTE=1: stderr={}", env_only.stderr);
    assert_eq!(env_only.status.code(), Some(0), "{context}");
    assert!(
        env_only.local_cargo_ran,
        "config force_local must run locally; {context}"
    );

    let run = run_isolated_exec(
        "force_local = true\n",
        true,
        true,
        false,
        &["--require-remote", "--", "cargo", "check"],
    );
    let context = format!("--require-remote: stderr={}", run.stderr);
    assert_eq!(run.status.code(), Some(1), "{context}");
    assert!(!run.local_cargo_ran, "cargo ran locally; {context}");
    assert_contains(
        &run.stderr,
        "remote required; refusing local fallback (force_local)",
    );
    assert_eq!(run.envelope()["outcome"], "refused", "{context}");
}
