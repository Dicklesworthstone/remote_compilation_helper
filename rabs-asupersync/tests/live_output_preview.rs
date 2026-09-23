//! Real managed processes: observations precede exit and never replace capture.
#![cfg(target_os = "linux")]

use rabs_asupersync::process_groups::{ManagedProcessGroup, members_from_proc};
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::{DrainLimits, LaneDrain};
use rabs_asupersync::stream_drain::preview::{LiveOutputPreview, MAX_PREVIEW_BYTES, PreviewStream};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn start(script: &str, root: &Path) -> ManagedProcessGroup {
    let mut command = Command::new("sh");
    command.args(["-c", script]).env("GATE", root.join("continue"))
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap()
}

fn bytes(lane: &LaneDrain) -> Vec<u8> {
    let mut bytes = lane.resident().to_vec();
    if let Some(spill) = lane.spill() { bytes.extend(fs::read(&spill.path).unwrap()); }
    assert_eq!(bytes.len() as u64, lane.total_bytes());
    bytes
}

#[test]
fn both_binary_streams_are_visible_while_the_real_child_waits_for_the_observer() {
    let root = tempfile::tempdir().unwrap();
    let preview = Arc::new(LiveOutputPreview::default());
    let group = start("printf 'out\\000\\377'; printf 'err\\000\\377' >&2; while [ ! -e \"$GATE\" ]; do sleep 0.01; done; printf after; printf tail >&2", root.path());
    let pgid = group.pgid();
    let until = Instant::now() + Duration::from_secs(5);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut released = false;
    let output = group.wait_with_bounded_drain_preview(
        &DrainLimits { resident_bound: 2, spill_dir: root.path().join("spill") },
        128, Some(Arc::clone(&preview)), || {
            for (stream, observed) in [(PreviewStream::Stdout, &mut stdout), (PreviewStream::Stderr, &mut stderr)] {
                if let Some(segment) = preview.take(stream) {
                    assert_eq!(segment.offset, observed.len() as u64);
                    assert_eq!(segment.skipped_bytes, 0);
                    observed.extend(segment.bytes);
                }
            }
            if !released && stdout == b"out\0\xff" && stderr == b"err\0\xff" {
                fs::write(root.path().join("continue"), b"go").unwrap();
                released = true;
            }
            Instant::now() >= until
        },
    ).unwrap();
    assert!(released, "previews were available only after process completion");
    assert!(output.status.success());
    assert_eq!(bytes(&output.stdout), b"out\0\xffafter");
    assert_eq!(bytes(&output.stderr), b"err\0\xfftail");
    assert_eq!(output.residual_group_members, 0);
    assert!(members_from_proc(pgid).is_empty());
}

#[test]
fn absent_consumer_drops_only_preview_prefixes_not_the_captured_transcript() {
    let root = tempfile::tempdir().unwrap();
    let preview = Arc::new(LiveOutputPreview::default());
    let group = start("head -c 131072 /dev/zero; printf complete >&2", root.path());
    let until = Instant::now() + Duration::from_secs(5);
    let output = group.wait_with_bounded_drain_preview(
        &DrainLimits { resident_bound: 31, spill_dir: root.path().join("spill") },
        262144, Some(Arc::clone(&preview)), || Instant::now() >= until,
    ).unwrap();
    assert!(output.status.success());
    assert_eq!(bytes(&output.stdout), vec![0; 131072]);
    assert_eq!(bytes(&output.stderr), b"complete");
    let segment = preview.take(PreviewStream::Stdout).unwrap();
    assert_eq!(segment.bytes, vec![0; MAX_PREVIEW_BYTES]);
    assert_eq!(segment.offset, 131072 - MAX_PREVIEW_BYTES as u64);
    assert_eq!(segment.skipped_bytes, segment.offset);
    assert_eq!(segment.observed_bytes, 131072);
}

#[test]
fn cancellation_after_preview_preserves_drained_bytes_and_resolves_descendants() {
    let root = tempfile::tempdir().unwrap();
    let preview = Arc::new(LiveOutputPreview::default());
    let group = start("printf before-cancel; sleep 30 & wait", root.path());
    let pgid = group.pgid();
    let until = Instant::now() + Duration::from_secs(5);
    let mut observed = Vec::new();
    let output = group.wait_with_bounded_drain_preview(
        &DrainLimits { resident_bound: 2, spill_dir: root.path().join("spill") },
        128, Some(Arc::clone(&preview)), || {
            if let Some(segment) = preview.take(PreviewStream::Stdout) { observed.extend(segment.bytes); }
            observed == b"before-cancel" || Instant::now() >= until
        },
    ).unwrap();
    assert_eq!(observed, b"before-cancel");
    assert!(!output.status.success());
    assert_eq!(bytes(&output.stdout), b"before-cancel");
    assert_eq!(output.residual_group_members, 0);
    assert!(members_from_proc(pgid).is_empty());
}

#[test]
fn early_preview_cannot_turn_later_quota_failure_into_complete_output() {
    let root = tempfile::tempdir().unwrap();
    let preview = Arc::new(LiveOutputPreview::default());
    let group = start("printf first; while [ ! -e \"$GATE\" ]; do sleep 0.01; done; printf exceeds-quota; sleep 30 & wait", root.path());
    let pgid = group.pgid();
    let until = Instant::now() + Duration::from_secs(5);
    let mut observed = Vec::new();
    let result = group.wait_with_bounded_drain_preview(
        &DrainLimits { resident_bound: 2, spill_dir: root.path().join("spill") },
        5, Some(Arc::clone(&preview)), || {
            if let Some(segment) = preview.take(PreviewStream::Stdout) { observed.extend(segment.bytes); }
            if observed == b"first" { fs::write(root.path().join("continue"), b"go").unwrap(); }
            Instant::now() >= until
        },
    );
    assert_eq!(observed, b"first");
    assert!(result.unwrap_err().to_string().contains("capture exceeds 5 bytes"));
    assert!(members_from_proc(pgid).is_empty());
}
