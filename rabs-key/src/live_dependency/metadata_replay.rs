//! Select an exact, ordered stderr prefix whose artifact events name only
//! committed metadata and subscriber-ready dep-info. The caller must install
//! and verify every metadata/dep-info output before emitting it; this helper
//! grants no output or serving authority.

use super::{
    DependencyActionPlan, artifact_event_fields, canonicalize_compiler_transcript,
    transcript_observations,
};
use crate::output_declarations::OutputClass;
use std::collections::BTreeSet;

/// Find a continuous prefix of the subscriber-rendered compiler transcript
/// ending at its last metadata artifact notification. Rustc reports dep-info
/// before metadata, so both roles must already be installed by the caller.
/// Diagnostics, whitespace, JSON field order and line endings remain byte-for-
/// byte unchanged. A tail output notification before metadata, a duplicate
/// head event, or missing metadata notifications disables early replay; the complete transcript can
/// still be replayed after all outputs are ready.
///
/// # Errors
/// The transcript fails the same strict artifact/path admission as an ordinary
/// cached result. A permissive JSON discriminator must never authorize replay.
pub fn metadata_replay_prefix_len(
    rendered: &[u8],
    plan: &DependencyActionPlan,
) -> Result<Option<usize>, &'static str> {
    // Revalidate the rendered path fields, including escaped/ambiguous events.
    // Selection is not a second, weaker transcript admission grammar.
    canonicalize_compiler_transcript(rendered, plan)?;
    let mut remaining = BTreeSet::new();
    for output in &plan.outputs.declarations {
        if output.class == OutputClass::ProvisionalMetadata {
            if !output.virtual_path.ends_with(".rmeta") {
                return Ok(None);
            }
            remaining.insert(output.virtual_path.as_bytes());
        }
    }
    if remaining.is_empty() {
        return Ok(None);
    }
    let mut prefix = 0;
    let mut offset = 0;
    let mut tail_event = false;
    let mut notified = BTreeSet::new();
    for line in rendered.split_inclusive(|byte| *byte == b'\n') {
        offset += line.len();
        if !transcript_observations(line, plan)?.0 {
            continue;
        }
        let (path, emit) =
            artifact_event_fields(line).ok_or("unsupported compiler artifact notification")?;
        if emit != b"metadata" && emit != b"dep-info" {
            tail_event = true;
            continue;
        }
        let relative = line[path]
            .strip_prefix(plan.out_dir.as_bytes())
            .and_then(|path| path.strip_prefix(b"/"))
            .ok_or("compiler artifact is outside the output directory")?;
        if !notified.insert(relative) {
            return Ok(None);
        }
        if emit == b"metadata" {
            if tail_event || !remaining.remove(relative) {
                return Ok(None);
            }
            prefix = offset;
        }
    }
    Ok((prefix != 0 && remaining.is_empty()).then_some(prefix))
}
