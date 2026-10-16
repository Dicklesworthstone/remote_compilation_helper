//! Finish detached recovery's daemon reservation before acknowledging the client.
//! Output retirement is not slot release. The original wrapper may have died
//! before its release request, or that request's reply may have been lost.
use super::{DurableJobLease, DurableLeaseWriter, RecoveryRecipe, load_recipe};
use crate::hook::artifact_patterns::kind_produces_transferable_artifacts;
use anyhow::{Context, Result};
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_REPLY_BYTES: u64 = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A single pinned endpoint for status, release and readback. Every operation
/// has a whole-request deadline and a bounded response, including on errors.
pub(super) async fn request(socket: &str, command: &str) -> Result<String> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut stream = UnixStream::connect(socket).await?;
        stream.write_all(command.as_bytes()).await?;
        stream.shutdown().await?;
        let mut bytes = Vec::new();
        stream
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .await?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_REPLY_BYTES,
            "oversized recovery daemon reply"
        );
        String::from_utf8(bytes).context("non-UTF-8 recovery daemon reply")
    })
    .await
    .context("recovery daemon request timed out; completion remains pending")?
}

fn body(response: &str) -> Result<Value> {
    anyhow::ensure!(
        response.len() as u64 <= MAX_REPLY_BYTES,
        "oversized recovery daemon reply"
    );
    let (header, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .context("incomplete recovery daemon response")?;
    let mut status = header.lines().next().unwrap_or_default().split_whitespace();
    anyhow::ensure!(
        matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) && status.next() == Some("200"),
        "recovery daemon refused the request"
    );
    serde_json::from_str(body).context("invalid recovery daemon JSON")
}

fn matches_record(record: &Value, build_id: u64, worker: &str) -> bool {
    record["id"].as_u64() == Some(build_id) && record["worker_id"].as_str() == Some(worker)
}

/// A completed receipt proves reservation accounting, not artifact delivery.
/// Cancellation may already have recorded a different exit from the worker's
/// completion/delivery result. Keep both facts rather than changing either one.
fn completed(reply: &Value, build_id: u64, worker: &str, wrapper: &str) -> Result<i32> {
    anyhow::ensure!(
        reply["status"] == "completed"
            && reply["local_wrapper_id"].as_str() == Some(wrapper)
            && matches_record(&reply["record"], build_id, worker),
        "daemon has no exact terminal receipt for recovered wrapper/build/worker"
    );
    reply["record"]["exit_code"]
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
        .context("daemon completion has no valid exit code")
}

/// The aggregate return/retirement flags cannot substitute for required phase
/// checkpoints. In particular, implicit Make outputs have no native/Cargo
/// contract to catch an incomplete phase at this final handoff (#107).
/// Validate retained evidence only: another build may legitimately have
/// replaced a shared output path since this invocation published it.
fn validate_successful_delivery(recipe: &RecoveryRecipe) -> Result<()> {
    if recipe.returned != Some(0) {
        // A truthful failed delivery may have incomplete phases. It must still
        // reconcile its reservation, retaining the original compiler outcome.
        return Ok(());
    }
    anyhow::ensure!(
        recipe.prepared
            && recipe.execution_started
            && !recipe.preparation_cancelled
            && recipe.exit_code == Some(0),
        "successful recovery contradicts its admitted execution outcome"
    );
    let required_artifacts = kind_produces_transferable_artifacts(recipe.kind);
    for phase in &recipe.phases {
        anyhow::ensure!(
            phase.pending.is_none(),
            "successful recovery still has a pending publication in {}; ownership retained",
            phase.name
        );
        let captured_output = recipe.cargo_output_capture.is_some() && phase.output_gate;
        if required_artifacts
            || phase.result_dir.is_some()
            || phase.native_outputs.is_some()
            || captured_output
        {
            anyhow::ensure!(
                phase.complete
                    && phase.missing_result.is_none()
                    && (!captured_output
                        || phase
                            .cargo_outputs
                            .as_ref()
                            .is_some_and(|contract| !contract.required_files.is_empty())),
                "successful recovery has incomplete required delivery in {}; ownership retained",
                phase.name
            );
            for relative in phase
                .native_outputs
                .iter()
                .flat_map(|contract| &contract.required_files)
                .chain(
                    phase
                        .cargo_outputs
                        .iter()
                        .flat_map(|contract| &contract.required_files),
                )
            {
                anyhow::ensure!(
                    phase.published.contains_key(relative),
                    "successful recovery lacks a required publication checkpoint for {}; ownership retained",
                    relative.display()
                );
            }
        }
    }
    Ok(())
}

/// Refuse a premature success both when loading old journals and BEFORE a
/// live writer publishes `returned = 0`. Waiting for `finish` is too late:
/// detached recovery retires sources before that final daemon handoff.
/// Pending collection and truthful failures retain their existing semantics.
/// Do not compare the outer exit here: recovery can deliver successfully
/// while the wrapper still records its original retrieval failure (102).
pub(super) fn validate_recorded_delivery(lease: &DurableJobLease) -> Result<()> {
    let Some(value) = lease.recovery.as_ref() else {
        return Ok(());
    };
    if value.get("returned").and_then(Value::as_i64) != Some(0) {
        return Ok(());
    }
    let recipe: RecoveryRecipe = serde_json::from_value(value.clone())
        .context("successful recovery has an invalid retained delivery recipe")?;
    anyhow::ensure!(
        recipe.version == 2
            && recipe.wrapper_id == lease.identity.local_wrapper_id
            && recipe.build_id > 0
            && Some(recipe.build_id) == lease.identity.remote_build_id
            && lease.worker_id.as_deref() == Some(recipe.worker.id.as_str()),
        "successful recovery has a different delivery identity; ownership retained"
    );
    validate_successful_delivery(&recipe)
}

/// Matches rchd's stuck-build hard cap (`should_remediate`).
const DAEMON_ABSENCE_MIN_AGE_MS: u64 = 24 * 60 * 60 * 1000;

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn daemon_absence_is_conclusive(lease: &crate::hook::DurableJobLease, now_unix_ms: u64) -> bool {
    lease.heartbeat_unix_ms > 0
        && now_unix_ms.saturating_sub(lease.heartbeat_unix_ms) >= DAEMON_ABSENCE_MIN_AGE_MS
}

/// Caller holds the same-wrapper recovery lock and has proved the original
/// wrapper absent. Never release based on an exit code, age or PID alone.
pub(super) async fn finish(
    writer: &DurableLeaseWriter,
    mut send: impl AsyncFnMut(&str) -> Result<String>,
) -> Result<()> {
    let lease = writer.snapshot();
    let mut recipe = load_recipe(writer)?;
    let exit = recipe
        .returned
        .context("recovery delivery is not settled")?;
    validate_successful_delivery(&recipe)?;
    anyhow::ensure!(
        recipe.retired
            && recipe.build_id > 0
            && !recipe.worker.id.as_str().is_empty()
            && lease.exit_code == Some(exit)
            && (recipe.retire_root.is_none() || recipe.tree_retired)
            && (recipe.pair.is_none() || recipe.pair_released)
            && (recipe.source_roots.is_empty() || recipe.sources_released),
        "recovery cannot release a reservation before exact delivery and source retirement"
    );
    let wrapper = recipe.wrapper_id.as_str();
    let worker = recipe.worker.id.as_str();
    let build_id = recipe.build_id;
    let encode = super::super::super::daemon_ipc::urlencoding_encode;
    let query = format!(
        "GET /builds/{build_id}?local_wrapper_id={}\n",
        encode(wrapper)
    );
    let mut reply = body(&send(&query).await?)?;
    if reply["status"] == "active" {
        anyhow::ensure!(
            recipe.daemon_exit_code.is_none(),
            "daemon reports active ownership after its persisted same-job receipt; release refused"
        );
        let active = &reply["active"];
        anyhow::ensure!(
            matches_record(active, build_id, worker)
                && active["local_wrapper_id"].as_str() == Some(wrapper),
            "active daemon reservation belongs to another identity; release refused"
        );
        let slots = active["slots"]
            .as_u64()
            .and_then(|slots| u32::try_from(slots).ok())
            .context("active daemon reservation has no valid slot count")?;
        let release = format!(
            "POST /release-worker?worker={}&slots={slots}&build_id={build_id}&local_wrapper_id={}&exit_code={exit}\n",
            encode(worker),
            encode(wrapper)
        );
        // A 200 status alone is insufficient: the release endpoint also treats
        // duplicate/unknown releases as no-ops. Conversely, a lost reply does
        // not prove failure. In both cases read the identity-bound tombstone.
        if let Err(error) = send(&release).await {
            tracing::warn!(build_id, %error, "Recovery release reply lost; verifying terminal ownership");
        }
        reply = body(&send(&query).await?)?;
    }
    if reply["status"] == "not_found" {
        // The daemon forgets completed builds and pre-2.1.16 reservations, so
        // a long-dead lease could never settle (bd-ey7fr). Absence is only
        // conclusive after the stuck detector's 24h cap: by then any
        // reservation re-adopted from durable ownership was remediated.
        anyhow::ensure!(
            daemon_absence_is_conclusive(&lease, unix_ms_now()),
            "daemon has no record of recovered build {build_id}; acknowledgement waits until the lease is 24h old"
        );
        anyhow::ensure!(
            writer.snapshot() == lease,
            "recovery journal changed during daemon reconciliation; acknowledgement refused"
        );
        recipe.daemon_record_absent = true;
        writer.set_recovery(serde_json::to_value(recipe)?)?;
        return writer.acknowledge_terminal();
    }
    let daemon_exit = completed(&reply, build_id, worker, wrapper)?;
    anyhow::ensure!(
        recipe
            .daemon_exit_code
            .is_none_or(|recorded| recorded == daemon_exit),
        "daemon completion contradicts its persisted same-job receipt; acknowledgement refused"
    );
    anyhow::ensure!(
        writer.snapshot() == lease,
        "recovery journal changed during daemon reconciliation; acknowledgement refused"
    );
    if daemon_exit != exit {
        tracing::warn!(
            build_id,
            daemon_exit,
            delivery_exit = exit,
            "Recovered delivery outcome differs from the daemon's earlier completion"
        );
    }
    // Persist the daemon fact first. A crash between this write and local ack
    // resumes via readback, without another artifact write or workload launch.
    recipe.daemon_exit_code = Some(daemon_exit);
    writer.set_recovery(serde_json::to_value(recipe)?)?;
    writer.acknowledge_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::{DurableJobLease, JobIdentity};
    use rch_common::{TransferConfig, WorkerConfig, WorkerId};
    use std::sync::{Arc, Mutex};

    fn fixture(exit: i32) -> (tempfile::TempDir, DurableLeaseWriter) {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("worker & one"),
            host: "unreachable.invalid".into(),
            user: "test".into(),
            identity_file: "/unused/key".into(),
            total_slots: 4,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        let writer = DurableLeaseWriter {
            path: directory.path().join("lease.json"),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(DurableJobLease::new(
                JobIdentity::new_local(),
                0,
                None,
                None,
                0,
                true,
                false,
                "fingerprint".into(),
            ))),
        };
        writer.admit(41, &worker.id).unwrap();
        super::super::RecoverySession::begin(
            &writer,
            &worker,
            vec!["/owned/project".into()],
            None,
            None,
            None,
            TransferConfig::default(),
            directory.path().to_owned(),
            "abc123".into(),
        )
        .unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.exit_code = Some(exit);
        recipe.returned = Some(exit);
        recipe.retired = true;
        recipe.sources_released = true;
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        writer.record_exit(exit).unwrap();
        (directory, writer)
    }

    fn response(value: Value) -> String {
        format!("HTTP/1.1 200 OK\r\n\r\n{value}")
    }

    fn active(writer: &DurableLeaseWriter) -> Value {
        let lease = writer.snapshot();
        serde_json::json!({"status":"active", "active": {
            "id":41, "worker_id":lease.worker_id,
            "local_wrapper_id":lease.identity.local_wrapper_id, "slots":4
        }})
    }

    fn terminal(writer: &DurableLeaseWriter, code: i32) -> Value {
        let lease = writer.snapshot();
        serde_json::json!({"status":"completed",
            "local_wrapper_id":lease.identity.local_wrapper_id,
            "record":{"id":41,"worker_id":lease.worker_id,"exit_code":code}
        })
    }

    fn output_phase(
        recipe: &RecoveryRecipe,
        result: bool,
        complete: bool,
    ) -> super::super::RecoveryPhase {
        super::super::RecoveryPhase {
            name: if result { "result:reports" } else { "project" }.into(),
            local: recipe.project_root.clone(),
            remote: "/unused/worker-outputs".into(),
            patterns: if result {
                Vec::new()
            } else {
                vec!["build/**".into()]
            },
            result_dir: result.then(|| "reports".into()),
            custom_target: false,
            output_gate: false,
            cargo_outputs: None,
            native_outputs: None,
            baseline: Default::default(),
            published: Default::default(),
            pending: None,
            complete,
            missing_result: None,
        }
    }

    #[tokio::test]
    async fn make_success_requires_every_required_phase_before_any_daemon_request() {
        // Inputs deliberately model contradictory retained checkpoints, not
        // observed compiler/source-release facts. No worker is contacted.
        for case in [
            "project",
            "partial-project",
            "report",
            "pending-project",
            "pending-report",
        ] {
            let (directory, writer) = fixture(0);
            let retained = directory.path().join("retained-output");
            std::fs::write(&retained, b"keep original output evidence").unwrap();
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.kind = Some(rch_common::CompilationKind::Make);
            recipe.phases = vec![
                output_phase(&recipe, false, true),
                output_phase(&recipe, true, true),
            ];
            match case {
                "project" | "partial-project" => {
                    recipe.phases[0].complete = false;
                    if case == "partial-project" {
                        recipe.phases[0].published.insert(
                            "build/one.o".into(),
                            blake3::hash(b"already published").to_hex().to_string(),
                        );
                    }
                }
                "report" => recipe.phases[1].complete = false,
                "pending-project" | "pending-report" => {
                    let index = usize::from(case == "pending-report");
                    recipe.phases[index].pending =
                        Some(("build/pending".into(), "retained-hash".into()));
                }
                _ => unreachable!(),
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let lease = writer.snapshot();
            let error = finish(&writer, async |_command: &str| {
                panic!("incomplete successful delivery contacted daemon: {case}")
            })
            .await
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("successful recovery"),
                "{case}: {error:#}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(writer.snapshot(), lease);
            assert!(!writer.snapshot().terminal_acknowledged);
            assert_eq!(
                std::fs::read(&retained).unwrap(),
                b"keep original output evidence"
            );
        }
    }

    #[tokio::test]
    async fn successful_handoff_cannot_invent_an_execution_outcome() {
        for case in ["unprepared", "unstarted", "cancelled", "failed", "unknown"] {
            let (_directory, writer) = fixture(0);
            let mut recipe = load_recipe(&writer).unwrap();
            match case {
                "unprepared" => recipe.prepared = false,
                "unstarted" => recipe.execution_started = false,
                "cancelled" => recipe.preparation_cancelled = true,
                "failed" => recipe.exit_code = Some(7),
                "unknown" => recipe.exit_code = None,
                _ => unreachable!(),
            }
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            assert!(
                finish(&writer, async |_command: &str| {
                    panic!("contradictory execution contacted daemon: {case}")
                })
                .await
                .is_err()
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert!(!writer.snapshot().terminal_acknowledged);
        }
    }

    #[tokio::test]
    async fn exact_output_contracts_need_their_published_fingerprints() {
        use crate::hook::artifact_patterns::direct_compiler::NativeOutputContract;
        use crate::hook::cargo_output_contract::{CargoOutputCapture, CargoOutputContract};
        for cargo in [false, true] {
            let (_directory, writer) = fixture(0);
            let mut recipe = load_recipe(&writer).unwrap();
            let mut phase = output_phase(&recipe, false, true);
            let relative = std::path::PathBuf::from(if cargo {
                "target/debug/app"
            } else {
                "build/app"
            });
            if cargo {
                recipe.kind = Some(rch_common::CompilationKind::CargoBuild);
                recipe.cargo_output_capture =
                    CargoOutputCapture::for_command(recipe.kind, "cargo build --bin app");
                assert!(recipe.cargo_output_capture.is_some());
                phase.output_gate = true;
                phase.cargo_outputs = Some(CargoOutputContract {
                    required_files: [relative.clone()].into(),
                });
            } else {
                recipe.kind = Some(rch_common::CompilationKind::Gcc);
                let contract = NativeOutputContract {
                    required_files: [relative.clone()].into(),
                };
                phase.patterns = contract.patterns().unwrap();
                phase.native_outputs = Some(contract);
            }
            recipe.phases = vec![phase];
            writer
                .set_recovery(serde_json::to_value(&recipe).unwrap())
                .unwrap();
            let before = std::fs::read(&writer.path).unwrap();
            let error = finish(&writer, async |_command: &str| {
                panic!("missing publication fingerprint contacted daemon")
            })
            .await
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("publication checkpoint"),
                "{error:#}"
            );
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            if cargo {
                let original = recipe.phases[0].cargo_outputs.clone();
                for invalid in [
                    None,
                    Some(CargoOutputContract {
                        required_files: Default::default(),
                    }),
                ] {
                    recipe.phases[0].cargo_outputs = invalid;
                    writer
                        .set_recovery(serde_json::to_value(&recipe).unwrap())
                        .unwrap();
                    let before = std::fs::read(&writer.path).unwrap();
                    assert!(
                        finish(&writer, async |_command: &str| {
                            panic!("missing captured output contract contacted daemon")
                        })
                        .await
                        .is_err()
                    );
                    assert_eq!(std::fs::read(&writer.path).unwrap(), before);
                }
                recipe.phases[0].cargo_outputs = original;
            }
            assert!(!writer.snapshot().terminal_acknowledged);
            // Valid historic checkpoints remain usable after another job
            // replaces the shared output. This handoff must not reopen a
            // released worker or rehash/adopt a later job's bytes.
            let current_output = recipe.project_root.join(&relative);
            std::fs::create_dir_all(current_output.parent().unwrap()).unwrap();
            std::fs::write(&current_output, b"a later build owns these bytes").unwrap();
            recipe.phases[0].published.insert(
                relative,
                blake3::hash(b"this invocation's published bytes")
                    .to_hex()
                    .to_string(),
            );
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            finish(&writer, async |command: &str| {
                assert!(command.starts_with("GET /builds/41?"));
                Ok(response(terminal(&writer, 0)))
            })
            .await
            .unwrap();
            assert!(writer.snapshot().terminal_acknowledged);
            assert_eq!(
                std::fs::read(current_output).unwrap(),
                b"a later build owns these bytes"
            );
        }
    }

    #[tokio::test]
    async fn phony_make_and_optional_streaming_artifacts_keep_their_success_semantics() {
        for (kind, complete) in [
            (rch_common::CompilationKind::Make, true),
            (rch_common::CompilationKind::CargoTest, false),
        ] {
            let (_directory, writer) = fixture(0);
            let mut recipe = load_recipe(&writer).unwrap();
            recipe.kind = Some(kind);
            recipe.phases = vec![output_phase(&recipe, false, complete)];
            assert!(recipe.phases[0].published.is_empty());
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            let mut queries = 0;
            finish(&writer, async |command: &str| {
                assert!(command.starts_with("GET /builds/41?"));
                queries += 1;
                Ok(response(terminal(&writer, 0)))
            })
            .await
            .unwrap();
            assert_eq!(queries, 1);
            assert!(writer.snapshot().terminal_acknowledged);
            assert_eq!(writer.snapshot().exit_code, Some(0));
        }
    }

    #[tokio::test]
    async fn failed_delivery_keeps_compiler_success_and_retained_incomplete_outputs() {
        let (directory, writer) = fixture(102);
        let retained = directory.path().join("retained-output");
        std::fs::write(&retained, b"retained worker bytes").unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.kind = Some(rch_common::CompilationKind::Make);
        recipe.exit_code = Some(0);
        recipe.phases = vec![output_phase(&recipe, false, false)];
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        finish(&writer, async |_command: &str| {
            Ok(response(terminal(&writer, 0)))
        })
        .await
        .unwrap();
        let recipe = load_recipe(&writer).unwrap();
        assert_eq!(recipe.exit_code, Some(0));
        assert_eq!(recipe.returned, Some(102));
        assert_eq!(recipe.daemon_exit_code, Some(0));
        assert!(!recipe.phases[0].complete);
        assert_eq!(writer.snapshot().exit_code, Some(102));
        assert!(writer.snapshot().terminal_acknowledged);
        assert_eq!(std::fs::read(retained).unwrap(), b"retained worker bytes");
    }

    #[tokio::test]
    async fn a_persisted_daemon_receipt_cannot_be_replaced_on_acknowledgment_retry() {
        let (_directory, writer) = fixture(102);
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.daemon_exit_code = Some(130);
        writer
            .set_recovery(serde_json::to_value(recipe).unwrap())
            .unwrap();
        let before = std::fs::read(&writer.path).unwrap();
        let lease = writer.snapshot();
        for contradictory in [terminal(&writer, 0), active(&writer)] {
            let mut queries = 0;
            let error = finish(&writer, async |command: &str| {
                assert!(command.starts_with("GET /builds/41?"));
                queries += 1;
                Ok(response(contradictory.clone()))
            })
            .await
            .unwrap_err();
            assert!(format!("{error:#}").contains("persisted same-job receipt"));
            assert_eq!(queries, 1);
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(writer.snapshot(), lease);
            assert!(!writer.snapshot().terminal_acknowledged);
        }
        finish(&writer, async |command: &str| {
            assert!(command.starts_with("GET /builds/41?"));
            Ok(response(terminal(&writer, 130)))
        })
        .await
        .unwrap();
        assert_eq!(writer.snapshot().exit_code, Some(102));
        assert_eq!(load_recipe(&writer).unwrap().daemon_exit_code, Some(130));
        assert!(writer.snapshot().terminal_acknowledged);
    }

    #[tokio::test]
    async fn recovery_releases_exact_slots_and_acknowledges_only_after_readback() {
        let (_directory, writer) = fixture(102);
        let mut calls = Vec::new();
        finish(&writer, async |command: &str| {
            assert!(!writer.snapshot().terminal_acknowledged);
            calls.push(command.to_owned());
            match calls.len() {
                1 => Ok(response(active(&writer))),
                2 => {
                    assert!(command.contains("worker=worker%20%26%20one&slots=4&build_id=41"));
                    assert!(command.contains("&exit_code=102\n"));
                    Ok("HTTP/1.1 200 OK\r\n".into())
                }
                3 => Ok(response(terminal(&writer, 102))),
                _ => panic!("unexpected request: {command}"),
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], calls[2]);
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        assert!(disk.terminal_acknowledged);
        assert_eq!(disk.exit_code, Some(102));
        assert_eq!(disk.recovery.unwrap()["daemon_exit_code"], 102);
    }

    #[tokio::test]
    async fn long_dead_build_the_daemon_forgot_settles_without_a_release() {
        let (_directory, writer) = fixture(1);
        writer.lease.lock().unwrap().heartbeat_unix_ms =
            unix_ms_now() - DAEMON_ABSENCE_MIN_AGE_MS - 60_000;
        writer.persist().unwrap();
        let mut calls = Vec::new();
        finish(&writer, async |command: &str| {
            calls.push(command.to_owned());
            Ok(response(serde_json::json!({"status":"not_found"})))
        })
        .await
        .unwrap();
        assert_eq!(calls.len(), 1, "absence must never send a release");
        assert!(calls[0].starts_with("GET /builds/41?"));
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        assert!(disk.terminal_acknowledged);
        assert_eq!(disk.exit_code, Some(1));
        let recovery = disk.recovery.unwrap();
        assert_eq!(recovery["daemon_record_absent"], true);
        assert!(recovery.get("daemon_exit_code").is_none());
    }

    #[test]
    fn daemon_absence_needs_a_known_heartbeat_older_than_the_stuck_cap() {
        let (_directory, writer) = fixture(1);
        let mut lease = writer.snapshot();
        let now = 10 * DAEMON_ABSENCE_MIN_AGE_MS;
        for (heartbeat, conclusive) in [
            (0, false),
            (now - DAEMON_ABSENCE_MIN_AGE_MS + 1, false),
            (now - DAEMON_ABSENCE_MIN_AGE_MS, true),
            (now + 5, false),
        ] {
            lease.heartbeat_unix_ms = heartbeat;
            assert_eq!(
                daemon_absence_is_conclusive(&lease, now),
                conclusive,
                "{heartbeat}"
            );
        }
    }

    #[tokio::test]
    async fn lost_release_reply_reconciles_without_a_second_release() {
        let (_directory, writer) = fixture(0);
        let mut count = 0;
        finish(&writer, async |_command: &str| {
            count += 1;
            match count {
                1 => Ok(response(active(&writer))),
                2 => anyhow::bail!("reply lost after durable commit"),
                3 => Ok(response(terminal(&writer, 0))),
                _ => panic!("duplicate release"),
            }
        })
        .await
        .unwrap();
        assert_eq!(count, 3);
        assert!(writer.snapshot().terminal_acknowledged);
    }

    #[tokio::test]
    async fn failed_readback_stays_pending_and_retry_uses_the_existing_tombstone() {
        let (_directory, writer) = fixture(137);
        let before = std::fs::read(&writer.path).unwrap();
        let mut count = 0;
        let result = finish(&writer, async |_command: &str| {
            count += 1;
            match count {
                1 => Ok(response(active(&writer))),
                2 => Ok("HTTP/1.1 200 OK\r\n".into()),
                _ => anyhow::bail!("daemon disconnected"),
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        let mut queries = 0;
        finish(&writer, async |command: &str| {
            assert!(command.starts_with("GET /builds/41?"));
            queries += 1;
            Ok(response(terminal(&writer, 130)))
        })
        .await
        .unwrap();
        assert_eq!(queries, 1);
        assert_eq!(writer.snapshot().exit_code, Some(137));
        assert_eq!(load_recipe(&writer).unwrap().daemon_exit_code, Some(130));
    }

    #[tokio::test]
    async fn missing_foreign_or_still_active_records_never_acknowledge() {
        let (_directory, writer) = fixture(101);
        let original = terminal(&writer, 101);
        let mut replies = vec![serde_json::json!({"status":"not_found"}), active(&writer)];
        for key in ["id", "worker_id", "exit_code"] {
            let mut changed = original.clone();
            changed["record"][key] = Value::Null;
            replies.push(changed);
        }
        let mut changed = original;
        changed["local_wrapper_id"] = Value::String("other".into());
        replies.push(changed);
        for invalid in replies {
            let before = std::fs::read(&writer.path).unwrap();
            let result = finish(&writer, async |_command: &str| {
                Ok(response(invalid.clone()))
            })
            .await;
            assert!(result.is_err(), "{invalid}");
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        }
        let mut foreign = active(&writer);
        foreign["active"]["worker_id"] = Value::String("other".into());
        let mut calls = 0;
        assert!(
            finish(&writer, async |_command: &str| {
                calls += 1;
                Ok(response(foreign.clone()))
            })
            .await
            .is_err()
        );
        assert_eq!(
            calls, 1,
            "foreign active ownership must never authorize POST"
        );
    }

    #[tokio::test]
    async fn incomplete_source_retirement_never_contacts_the_daemon() {
        let (_directory, writer) = fixture(0);
        let original = load_recipe(&writer).unwrap();
        for field in ["retired", "sources_released", "returned", "build_id"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[field] = match field {
                "retired" | "sources_released" => Value::Bool(false),
                "build_id" => Value::from(0),
                _ => Value::Null,
            };
            writer.set_recovery(value).unwrap();
            assert!(
                finish(&writer, async |_command: &str| {
                    panic!("unfinished or malformed ownership contacted daemon")
                })
                .await
                .is_err()
            );
        }
    }

    #[test]
    fn replies_require_complete_successful_http_and_typed_terminal_evidence() {
        for reply in [
            "HTTP/1.1 200 OK\r\n",
            "HTTP/1.1 500 Error\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\n\r\n{",
            "garbage 200 OK\n\n{}",
        ] {
            assert!(body(reply).is_err(), "{reply}");
        }
        assert!(body(&"x".repeat(MAX_REPLY_BYTES as usize + 1)).is_err());
    }

    #[tokio::test]
    async fn pinned_socket_transport_is_bounded_and_sends_the_request_verbatim() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let command = "GET /builds/41?local_wrapper_id=rchw-test\n";
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).await.unwrap();
            assert_eq!(received, command);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"status\":\"not_found\"}")
                .await
                .unwrap();
        };
        let client = request(socket.to_str().unwrap(), command);
        let (reply, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        assert_eq!(body(&reply.unwrap()).unwrap()["status"], "not_found");
    }

    #[tokio::test]
    async fn retired_recovery_resumes_at_daemon_handoff_without_contacting_worker() {
        let (_directory, writer) = fixture(102);
        writer.lease.lock().unwrap().wrapper_pid = 2_147_483_646;
        writer.persist().unwrap();
        let mut queries = 0;
        // Boxed: the debug-build recovery future overflowed the test thread's
        // stack and aborted the whole rch test binary.
        let exit = Box::pin(super::super::recover_job_with_daemon(
            &writer,
            async |command: &str| {
                assert!(command.starts_with("GET /builds/41?"));
                queries += 1;
                Ok(response(terminal(&writer, 102)))
            },
        ))
        .await
        .unwrap();
        assert_eq!(exit, 102);
        assert_eq!(queries, 1);
        assert!(writer.snapshot().terminal_acknowledged);
        // The remote worker is deliberately unreachable. A second pass must
        // remain read-only and not even call the daemon transport.
        assert_eq!(
            crate::hook::after_gate_release(|| Box::pin(super::super::recover_job_with_daemon(
                &writer,
                async |_command: &str| { panic!("acknowledged recovery contacted a peer") }
            )))
            .await
            .unwrap(),
            102
        );
    }
}
