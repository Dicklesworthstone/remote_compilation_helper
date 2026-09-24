//! Request-bound, lossy live diagnostics from the actual execution's pipe drain.
//! Preview reads never touch spools, wait for a compiler, change cancellation,
//! or create execution/result authority. Complete transcripts are separate.

use super::{ExecutionControl, ExecutionTask};
use rabs_asupersync::stream_drain::preview::{LiveOutputPreview, PreviewStream};
use serde_json::{Value, json};
use std::sync::Arc;

pub const OUTPUT_PREVIEW_VERSION: &str = "tail-v1";

impl ExecutionControl {
    /// The managed drain records only after ordinary capture accepts a chunk.
    /// Keeping this independent of capture/result locks prevents a preview
    /// consumer from holding up either the pipe reader or result publication.
    #[must_use]
    pub fn output_observer(&self) -> Arc<LiveOutputPreview> {
        Arc::clone(&self.preview)
    }
}

/// Serve only the selected in-session execution. `last_admitted` handles a
/// queued preview query overtaken by terminal completion: its empty inactive
/// reply is NOT a completed result, and does not reopen or read a retained spool.
/// Invalid queries are rejected before consuming either stream's preview cursor.
pub fn output_preview_reply(
    request: &Value,
    active: Option<&ExecutionTask>,
    last_admitted: Option<u64>,
) -> Result<Value, String> {
    if request["kind"] != "output-preview"
        || request.as_object().is_none_or(|fields| fields.len() != 2)
    {
        return Err("output preview requires exactly kind and request_id".into());
    }
    let id = request["request_id"].as_u64()
        .ok_or("output preview requires an unsigned request_id")?;
    match active {
        Some(task) if task.request_id() != id => return Err("unknown-output-preview-request".into()),
        None if last_admitted != Some(id) => return Err("unknown-output-preview-request".into()),
        _ => {}
    }
    let segments: Vec<_> = active.into_iter().flat_map(|task| {
        [PreviewStream::Stdout, PreviewStream::Stderr].into_iter().filter_map(move |stream| {
            task.control.preview.take(stream).map(|segment| json!({
                "stream":stream.name(), "offset":segment.offset,
                "data_hex":segment.bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "skipped_bytes":segment.skipped_bytes, "observed_bytes":segment.observed_bytes,
            }))
        })
    }).collect();
    Ok(json!({"kind":"output-preview", "version":OUTPUT_PREVIEW_VERSION,
        "request_id":id, "active":active.is_some(), "segments":segments,
        "complete":false, "publication_authorized":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{ExecutionCompletion, StopReason};
    use crate::session::{ExecResult, sha256_hex};
    use rabs_asupersync::stream_drain::preview::MAX_PREVIEW_BYTES;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    fn result(id: u64) -> ExecResult {
        ExecResult { request_id:id, exit_code:0, stdout_sha256:sha256_hex(b""),
            stderr_sha256:sha256_hex(b""), executed:true, residual_group_members:0,
            stdout_spill_bytes:0, stderr_spill_bytes:0, stdout_spill_path:None, stderr_spill_path:None }
    }
    fn finish(task: &mut ExecutionTask) -> Result<ExecutionCompletion, String> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Poll::Ready(done) = task.poll_completion(&mut Context::from_waker(Waker::noop())) {
                return done;
            }
            assert!(Instant::now() < until, "execution completion deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn query(id: u64) -> Value { json!({"kind":"output-preview", "request_id":id}) }
    fn task() -> (ExecutionTask, ExecutionControl) {
        let (sender, receiver) = mpsc::channel();
        let task = ExecutionTask::spawn(7, Duration::from_secs(5), move |control| {
            sender.send(control.clone()).unwrap();
            while control.reason().is_none() { std::thread::sleep(Duration::from_millis(1)); }
            result(7)
        }).unwrap();
        (task, receiver.recv_timeout(Duration::from_secs(2)).unwrap())
    }

    #[test]
    fn preview_queries_bind_identity_before_consuming_and_preserve_binary_streams() {
        let (mut task, control) = task();
        control.output_observer().record(PreviewStream::Stdout, 0, b"out\0\xff");
        control.output_observer().record(PreviewStream::Stderr, 0, "雪".as_bytes());
        for bad in [Value::Null, json!([]), query(8),
            json!({"kind":"output-preview", "request_id":7, "path":"/private"}),
            json!({"kind":"output-preview", "request_id":"7"})]
        {
            assert!(output_preview_reply(&bad, Some(&task), Some(7)).is_err());
        }
        let reply = output_preview_reply(&query(7), Some(&task), Some(7)).unwrap();
        assert_eq!(reply["segments"][0]["data_hex"], "6f757400ff");
        assert_eq!(reply["segments"][1]["data_hex"], "e99baa");
        assert_eq!(reply["segments"][0]["offset"], 0);
        assert_eq!(reply["segments"][0]["observed_bytes"], 5);
        assert_eq!(reply["active"], true);
        assert_eq!(reply["complete"], false);
        assert_eq!(reply["publication_authorized"], false);
        assert!(task.retained_result_digest().is_none());
        assert_eq!(output_preview_reply(&query(7), Some(&task), Some(7)).unwrap()["segments"], json!([]));
        task.cancel(StopReason::Cancelled);
        assert_eq!(finish(&mut task).unwrap().result.exit_code, 130);
    }

    #[test]
    fn slow_preview_reader_gets_a_bounded_tail_with_an_explicit_gap() {
        let (mut task, control) = task();
        control.output_observer().record(PreviewStream::Stdout, 0, &vec![0xff; MAX_PREVIEW_BYTES * 8]);
        let reply = output_preview_reply(&query(7), Some(&task), Some(7)).unwrap();
        let segment = &reply["segments"][0];
        assert_eq!(segment["data_hex"].as_str().unwrap().len(), 2 * MAX_PREVIEW_BYTES);
        assert_eq!(segment["offset"], 7 * MAX_PREVIEW_BYTES);
        assert_eq!(segment["skipped_bytes"], 7 * MAX_PREVIEW_BYTES);
        assert_eq!(segment["observed_bytes"], 8 * MAX_PREVIEW_BYTES);
        assert!(serde_json::to_vec(&reply).unwrap().len() < 36 * 1024);
        task.cancel(StopReason::SessionLost);
        assert_eq!(finish(&mut task).unwrap().stop_reason, Some(StopReason::SessionLost));
    }

    #[test]
    fn terminal_race_is_empty_not_a_result_and_never_exposes_another_execution() {
        let reply = output_preview_reply(&query(7), None, Some(7)).unwrap();
        assert_eq!(reply["active"], false);
        assert_eq!(reply["complete"], false);
        assert_eq!(reply["segments"], json!([]));
        assert!(reply.get("exit_code").is_none());
        assert!(output_preview_reply(&query(7), None, None).is_err());
        assert!(output_preview_reply(&query(7), None, Some(8)).is_err());
        let (task, _) = task();
        assert!(output_preview_reply(&query(8), Some(&task), Some(8)).is_err());
    }

    #[test]
    fn observed_bytes_never_satisfy_missing_complete_output_capture() {
        let mut task = ExecutionTask::spawn(9, Duration::from_secs(5), |control| {
            control.request_output_capture();
            control.output_observer().record(PreviewStream::Stdout, 0, b"not a transcript");
            result(9)
        }).unwrap();
        assert!(finish(&mut task).unwrap_err().contains("omitted requested output capture"));
        assert!(task.retained_result_digest().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_managed_child_produces_binary_preview_before_exit_and_complete_capture_after() {
        use crate::output::CapturedOutputs;
        use rabs_asupersync::process_groups::ManagedProcessGroup;
        use rabs_asupersync::region_tree::Attribution;
        use rabs_asupersync::stream_drain::DrainLimits;
        use std::process::{Command, Stdio};

        let root = tempfile::tempdir().unwrap();
        let worker_root = root.path().to_path_buf();
        let mut task = ExecutionTask::spawn(7, Duration::from_secs(5), move |control| {
            control.request_output_capture();
            let mut command = Command::new("sh");
            command.args(["-c", "printf 'out\\000\\377'; printf 'err\\000\\377' >&2; while [ ! -e \"$GATE\" ]; do sleep 0.01; done; printf tail"])
                .env("GATE", worker_root.join("continue"))
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
            let output = group.wait_with_bounded_drain_preview(
                &DrainLimits { resident_bound:2, spill_dir:worker_root.join("spill") },
                1024, Some(control.output_observer()), || control.reason().is_some(),
            ).unwrap();
            let capture = CapturedOutputs::from_lanes(&output.stdout, &output.stderr).unwrap();
            let mut result = result(7);
            result.exit_code = output.status.code().unwrap_or(125);
            result.stdout_sha256 = capture.stdout.sha256().to_owned();
            result.stderr_sha256 = capture.stderr.sha256().to_owned();
            result.residual_group_members = output.residual_group_members;
            control.retain_outputs(Ok(capture)).unwrap();
            result
        }).unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        let mut stdout = String::new();
        let mut stderr = String::new();
        while stdout != "6f757400ff" || stderr != "65727200ff" {
            let reply = output_preview_reply(&query(7), Some(&task), Some(7)).unwrap();
            for segment in reply["segments"].as_array().unwrap() {
                assert_eq!(segment["skipped_bytes"], 0);
                let bytes = segment["data_hex"].as_str().unwrap();
                if segment["stream"] == "stdout" { stdout.push_str(bytes); }
                else { stderr.push_str(bytes); }
            }
            assert!(Instant::now() < until, "live child produced no preview");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(task.poll_completion(&mut Context::from_waker(Waker::noop())).is_pending());
        std::fs::write(root.path().join("continue"), b"go").unwrap();
        let mut done = finish(&mut task).unwrap();
        assert_eq!(done.result.exit_code, 0);
        let output = done.outputs.as_mut().unwrap();
        assert_eq!(output.stdout.read_chunk(0, 1024).unwrap(), b"out\0\xfftail");
        assert_eq!(output.stderr.read_chunk(0, 1024).unwrap(), b"err\0\xff");
    }
}
