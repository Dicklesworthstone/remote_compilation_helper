//! Finish detached recovery's daemon reservation before acknowledging the client.
//! Output retirement is not slot release. The original wrapper may have died
//! before its release request, or that request's reply may have been lost.
use super::{DurableLeaseWriter, load_recipe};
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
    let daemon_exit = completed(&reply, build_id, worker, wrapper)?;
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
        let directory = tempfile::tempdir().unwrap();
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
            Box::pin(super::super::recover_job_with_daemon(
                &writer,
                async |_command: &str| { panic!("acknowledged recovery contacted a peer") }
            ))
            .await
            .unwrap(),
            102
        );
    }
}
