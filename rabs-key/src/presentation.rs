//! `PresentationContract` + transcript replay variants (bead F021;
//! invariant I24; plan §68; risk R55).
//!
//! One semantic result serves MANY presentations. The split:
//!
//! - the semantic `ActionKey` includes diagnostic/lint settings ONLY
//!   when they can alter exit behavior or artifacts (`-D warnings` is
//!   semantic; it changes exit codes — F003 keys it);
//! - color mode, terminal width, real-path translation, and human
//!   formatting live in the [`PresentationContract`], which digests
//!   into a [`PresentationVariantKey`] — a key over PRESENTATION, never
//!   part of the semantic key;
//! - **exact byte-transcript replay** requires a stored transcript
//!   variant matching the subscriber's variant key. When none matches,
//!   the decision is a CLEAN BYPASS to re-rendering from canonical
//!   events (or live execution) — never serving a wrong-variant
//!   transcript as if byte-exact, and never fragmenting the semantic
//!   key to manufacture a variant;
//! - canonical compiler events marked safely re-renderable let any
//!   variant be produced on demand; **uncertain fidelity bypasses
//!   transcript reuse** (fails toward re-render/live, not toward a
//!   possibly-wrong byte replay).

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for presentation variants.
pub const DOMAIN_PRESENTATION_VARIANT: &str = "rabs.presentation-variant.v1";

/// Color mode requested by the subscriber's terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ColorMode {
    Never,
    Always,
    Ansi256,
    TrueColor,
}

/// The presentation contract: everything about HOW output is shown.
/// Structurally disjoint from `ActionDescriptor` — there is no field
/// here a semantic key computation ever reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationContract {
    /// Color rendering mode.
    pub color: ColorMode,
    /// Terminal width for diagnostic wrapping.
    pub terminal_width: Option<u32>,
    /// Identity of the virtual→real path translation table applied when
    /// rendering paths for THIS subscriber.
    pub path_translation_digest: TypedDigest,
    /// Human formatting profile name (`"short"`, `"json"`, ...).
    pub format_profile: String,
}

/// Key over a presentation variant (never a semantic key input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationVariantKey(pub TypedDigest);

impl PresentationContract {
    /// Compute this contract's variant key.
    #[must_use]
    pub fn variant_key(&self) -> PresentationVariantKey {
        let mut enc = CanonicalEncoder::new();
        enc.u32(match self.color {
            ColorMode::Never => 1,
            ColorMode::Always => 2,
            ColorMode::Ansi256 => 3,
            ColorMode::TrueColor => 4,
        });
        match self.terminal_width {
            None => {
                enc.u32(0);
            }
            Some(w) => {
                enc.u32(1).u32(w);
            }
        }
        enc.str(self.path_translation_digest.domain)
            .bytes(&self.path_translation_digest.bytes)
            .str(&self.format_profile);
        PresentationVariantKey(compute(DOMAIN_PRESENTATION_VARIANT, &enc.finish()))
    }
}

/// Fidelity of the stored canonical event stream for re-rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderFidelity {
    /// Events verified safely re-renderable to any variant.
    SafelyReRenderable,
    /// Fidelity unknown/unverified — MUST bypass transcript reuse.
    Uncertain,
}

/// A stored transcript variant for one semantic result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTranscriptVariant {
    /// The variant this transcript was rendered under.
    pub variant_key: PresentationVariantKey,
    /// The transcript object bytes digest.
    pub transcript_digest: TypedDigest,
}

/// How to satisfy a subscriber's transcript request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptDecision {
    /// Byte-exact stored transcript for the requested variant.
    ServeStoredByteExact(TypedDigest),
    /// No matching variant (or byte-exactness not required): re-render
    /// from canonical events for this subscriber's presentation.
    ReRenderFromEvents,
    /// Events' fidelity uncertain (or no events): produce output from a
    /// fresh/live execution path; stored transcripts are not reused.
    BypassTranscriptReuse,
}

/// Decide transcript service for a subscriber.
///
/// `require_byte_exact` is the subscriber's demand for byte-identical
/// replay (IDE capture comparison, CI log diffing).
#[must_use]
pub fn decide_transcript(
    requested: &PresentationVariantKey,
    stored: &[StoredTranscriptVariant],
    fidelity: RenderFidelity,
    require_byte_exact: bool,
) -> TranscriptDecision {
    if let Some(hit) = stored.iter().find(|v| v.variant_key == *requested) {
        // A byte-exact stored variant serves regardless of fidelity —
        // it IS the bytes that variant produced.
        return TranscriptDecision::ServeStoredByteExact(hit.transcript_digest.clone());
    }
    if require_byte_exact {
        // Byte replay requested, no matching variant: CLEAN bypass.
        // Serving a different variant's bytes as "exact" is forbidden,
        // and the semantic key is never fragmented to mint one.
        return TranscriptDecision::BypassTranscriptReuse;
    }
    match fidelity {
        RenderFidelity::SafelyReRenderable => TranscriptDecision::ReRenderFromEvents,
        RenderFidelity::Uncertain => TranscriptDecision::BypassTranscriptReuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn contract(color: ColorMode, width: Option<u32>) -> PresentationContract {
        PresentationContract {
            color,
            terminal_width: width,
            path_translation_digest: d("rabs.path-translation.v1", 1),
            format_profile: "short".into(),
        }
    }

    #[test]
    fn color_only_difference_hits_the_same_semantic_result() {
        // R55 acceptance: two subscribers differing only in color/width
        // have different VARIANT keys but — structurally — the same
        // semantic key: PresentationContract has no channel into
        // ActionDescriptor (no shared fields, no digest slot). The
        // variant keys differing while semantics are untouched IS the
        // non-fragmentation property.
        let a = contract(ColorMode::Always, Some(120)).variant_key();
        let b = contract(ColorMode::Never, Some(80)).variant_key();
        assert_ne!(a, b, "different presentations, different variants");
        // The semantic result they consult is selected by ActionKey
        // alone; nothing in this module takes or returns a semantic
        // key — the type system carries the R55 guarantee.
    }

    #[test]
    fn byte_replay_with_matching_variant_serves_stored_bytes() {
        let variant = contract(ColorMode::Always, Some(120)).variant_key();
        let stored = vec![StoredTranscriptVariant {
            variant_key: variant.clone(),
            transcript_digest: d("rabs.transcript.v1", 9),
        }];
        assert_eq!(
            decide_transcript(&variant, &stored, RenderFidelity::SafelyReRenderable, true),
            TranscriptDecision::ServeStoredByteExact(d("rabs.transcript.v1", 9))
        );
    }

    #[test]
    fn byte_replay_without_a_variant_bypasses_cleanly() {
        // THE acceptance case: byte-exact replay requested, stored
        // transcript exists only for ANOTHER variant — clean bypass,
        // never the wrong bytes, never key fragmentation.
        let requested = contract(ColorMode::Never, None).variant_key();
        let other = contract(ColorMode::Always, Some(120)).variant_key();
        let stored = vec![StoredTranscriptVariant {
            variant_key: other,
            transcript_digest: d("rabs.transcript.v1", 9),
        }];
        assert_eq!(
            decide_transcript(
                &requested,
                &stored,
                RenderFidelity::SafelyReRenderable,
                true
            ),
            TranscriptDecision::BypassTranscriptReuse
        );
    }

    #[test]
    fn re_renderable_events_serve_any_variant_without_byte_exactness() {
        let requested = contract(ColorMode::TrueColor, Some(200)).variant_key();
        assert_eq!(
            decide_transcript(&requested, &[], RenderFidelity::SafelyReRenderable, false),
            TranscriptDecision::ReRenderFromEvents
        );
    }

    #[test]
    fn uncertain_fidelity_bypasses_transcript_reuse() {
        let requested = contract(ColorMode::Never, None).variant_key();
        assert_eq!(
            decide_transcript(&requested, &[], RenderFidelity::Uncertain, false),
            TranscriptDecision::BypassTranscriptReuse
        );
    }

    #[test]
    fn every_contract_field_moves_the_variant_key() {
        let base = contract(ColorMode::Always, Some(120)).variant_key();
        assert_ne!(base, contract(ColorMode::Ansi256, Some(120)).variant_key());
        assert_ne!(base, contract(ColorMode::Always, Some(121)).variant_key());
        assert_ne!(base, contract(ColorMode::Always, None).variant_key());
        let mut m = contract(ColorMode::Always, Some(120));
        m.path_translation_digest = d("rabs.path-translation.v1", 2);
        assert_ne!(base, m.variant_key());
        let mut m = contract(ColorMode::Always, Some(120));
        m.format_profile = "json".into();
        assert_ne!(base, m.variant_key());
    }
}
