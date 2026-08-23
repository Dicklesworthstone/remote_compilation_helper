//! Presentation-variant matrix tests (bead K014; risk R55; the
//! acceptance suite over the F021 decision core).
//!
//! One semantic result serves MANY presentations. These fixtures pin
//! the whole matrix at the decision layer:
//!
//! - a 4×3×2×2 grid of presentation contracts (color × width ×
//!   profile × path translation) yields 48 pairwise-DISTINCT variant
//!   keys — and the same contract always digests to the same key;
//! - the complete `decide_transcript` truth table: a matching stored
//!   variant serves byte-exact REGARDLESS of fidelity or exactness
//!   demand (stored bytes are self-certifying — they ARE that
//!   variant's output; fidelity governs only re-rendering); no match
//!   plus byte-exactness is a CLEAN bypass (never wrong-variant
//!   bytes, never semantic-key fragmentation); no match without
//!   byte-exactness re-renders iff events are safely re-renderable;
//! - uncertain fidelity bypasses transcript reuse on every path that
//!   would need the event stream;
//! - several subscribers with different contracts over ONE semantic
//!   result are each served per their own key from one shared store.

use rabs_key::presentation::{
    ColorMode, PresentationContract, RenderFidelity, StoredTranscriptVariant, TranscriptDecision,
    decide_transcript,
};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn contract(
    color: ColorMode,
    width: Option<u32>,
    profile: &str,
    path_tag: u8,
) -> PresentationContract {
    PresentationContract {
        color,
        terminal_width: width,
        path_translation_digest: digest("rabs.path-translation.v1", path_tag),
        format_profile: profile.to_owned(),
    }
}

const COLORS: [ColorMode; 4] = [
    ColorMode::Never,
    ColorMode::Always,
    ColorMode::Ansi256,
    ColorMode::TrueColor,
];
const WIDTHS: [Option<u32>; 3] = [None, Some(80), Some(120)];
const PROFILES: [&str; 2] = ["short", "json"];

#[test]
fn the_full_variant_matrix_is_pairwise_distinct_and_deterministic() {
    let mut keys = Vec::new();
    for color in COLORS {
        for width in WIDTHS {
            for profile in PROFILES {
                for path_tag in [1u8, 2] {
                    let c = contract(color, width, profile, path_tag);
                    // Determinism: the SAME contract digests identically.
                    assert_eq!(
                        c.variant_key(),
                        c.variant_key(),
                        "{color:?} {width:?} {profile}"
                    );
                    keys.push((
                        format!("{color:?}/{width:?}/{profile}/{path_tag}"),
                        c.variant_key(),
                    ));
                }
            }
        }
    }
    // Pairwise distinct across the whole 48-cell matrix.
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].1, keys[j].1,
                "variant-key collision between {} and {}",
                keys[i].0, keys[j].0
            );
        }
    }
}

#[test]
fn one_semantic_result_serves_many_subscribers_from_one_store() {
    // ONE stored set for one semantic result; three subscribers with
    // different contracts. Each gets served per THEIR key alone.
    let dark_short = contract(ColorMode::Never, Some(80), "short", 1).variant_key();
    let light_json = contract(ColorMode::Always, None, "json", 2).variant_key();
    let truecolor_wide = contract(ColorMode::TrueColor, Some(200), "short", 1).variant_key();
    let store = vec![
        StoredTranscriptVariant {
            variant_key: dark_short.clone(),
            transcript_digest: digest("rabs.transcript.v1", 1),
        },
        StoredTranscriptVariant {
            variant_key: light_json.clone(),
            transcript_digest: digest("rabs.transcript.v1", 2),
        },
    ];
    // Matched subscribers: byte-exact, each their OWN bytes.
    assert_eq!(
        decide_transcript(
            &dark_short,
            &store,
            RenderFidelity::SafelyReRenderable,
            true
        ),
        TranscriptDecision::ServeStoredByteExact(digest("rabs.transcript.v1", 1))
    );
    assert_eq!(
        decide_transcript(&light_json, &store, RenderFidelity::Uncertain, false),
        TranscriptDecision::ServeStoredByteExact(digest("rabs.transcript.v1", 2)),
        "a matching stored variant is self-certifying: fidelity gates \
         RE-RENDERING, never the variant's own recorded bytes"
    );
    // Unmatched subscriber: safe re-render for their variant.
    assert_eq!(
        decide_transcript(
            &truecolor_wide,
            &store,
            RenderFidelity::SafelyReRenderable,
            false
        ),
        TranscriptDecision::ReRenderFromEvents
    );
}

#[test]
fn the_decide_transcript_truth_table_holds_exactly() {
    let requested = contract(ColorMode::Ansi256, Some(80), "short", 1).variant_key();
    let other = contract(ColorMode::Never, None, "json", 2).variant_key();
    let matched = vec![StoredTranscriptVariant {
        variant_key: requested.clone(),
        transcript_digest: digest("rabs.transcript.v1", 7),
    }];
    let unmatched = vec![StoredTranscriptVariant {
        variant_key: other,
        transcript_digest: digest("rabs.transcript.v1", 8),
    }];

    // Row: MATCHED variant — served byte-exact under all four
    // fidelity/exactness combinations.
    for fidelity in [
        RenderFidelity::SafelyReRenderable,
        RenderFidelity::Uncertain,
    ] {
        for exact in [true, false] {
            assert_eq!(
                decide_transcript(&requested, &matched, fidelity, exact),
                TranscriptDecision::ServeStoredByteExact(digest("rabs.transcript.v1", 7)),
                "matched variant must serve stored bytes (fidelity={fidelity:?}, exact={exact})"
            );
        }
    }

    // Row: UNMATCHED + byte-exact demanded — clean bypass under both
    // fidelities (wrong-variant bytes are forbidden outright).
    for fidelity in [
        RenderFidelity::SafelyReRenderable,
        RenderFidelity::Uncertain,
    ] {
        assert_eq!(
            decide_transcript(&requested, &unmatched, fidelity, true),
            TranscriptDecision::BypassTranscriptReuse,
            "no-match + byte-exact must bypass (fidelity={fidelity:?})"
        );
    }

    // Row: UNMATCHED, no exactness — fidelity decides.
    assert_eq!(
        decide_transcript(
            &requested,
            &unmatched,
            RenderFidelity::SafelyReRenderable,
            false
        ),
        TranscriptDecision::ReRenderFromEvents
    );
    assert_eq!(
        decide_transcript(&requested, &unmatched, RenderFidelity::Uncertain, false),
        TranscriptDecision::BypassTranscriptReuse
    );

    // Row: EMPTY store behaves as unmatched.
    assert_eq!(
        decide_transcript(&requested, &[], RenderFidelity::SafelyReRenderable, false),
        TranscriptDecision::ReRenderFromEvents
    );
    assert_eq!(
        decide_transcript(&requested, &[], RenderFidelity::Uncertain, true),
        TranscriptDecision::BypassTranscriptReuse
    );
}

#[test]
fn uncertain_fidelity_never_reaches_the_re_render_path() {
    // R55's fail-toward-live rule: when event fidelity is uncertain,
    // NO requested variant can extract a re-render — including one
    // whose variant happens to be first in the store under a DIFFERENT
    // key... i.e., even a near-miss must not be talked into reuse.
    let near_miss = contract(ColorMode::Ansi256, Some(80), "short", 1).variant_key();
    let actual = contract(ColorMode::Ansi256, Some(81), "short", 1).variant_key();
    assert_ne!(near_miss, actual, "one width step is a different variant");
    let store = vec![StoredTranscriptVariant {
        variant_key: near_miss,
        transcript_digest: digest("rabs.transcript.v1", 9),
    }];
    assert_eq!(
        decide_transcript(&actual, &store, RenderFidelity::Uncertain, false),
        TranscriptDecision::BypassTranscriptReuse
    );
}
