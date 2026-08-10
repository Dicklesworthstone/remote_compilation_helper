//! Virtual-to-real JSON diagnostic rewriting (bead D008; plan §27).
//!
//! Every edge maintains, per subscriber, a canonical-virtual-path →
//! requesting-worktree-path mapping and applies it to canonical
//! structured compiler events, rendered diagnostics, and `rch why`
//! output. Three distinctions this module makes structural, because
//! blurring any of them corrupts either Cargo or provenance:
//!
//! 1. **rustc's artifact-notification is replayed VERBATIM.** That JSON
//!    line carries the exact output path Cargo requested and is what
//!    Cargo's current process is blocked waiting on — rewriting it
//!    would hand Cargo a path it never asked for. It is detected
//!    structurally (an `"artifact"` key) and passed through untouched.
//! 2. **Cargo's outward `compiler-artifact` message is Cargo-generated
//!    and never synthesized here.** This module exposes no constructor
//!    for it — it only TRANSLATES payloads that already exist; the
//!    `{"reason": "compiler-artifact"}` shape is explicitly not
//!    confused with rustc's internal notification.
//! 3. **A translation serves a subscriber only when it is COMPLETE.**
//!    If any canonical marker survives rewriting (a path with no
//!    mapping entry), the outcome is a typed [`TranslationOutcome::Bypass`]
//!    listing the untranslated strings — the caller falls back to a
//!    presentation variant or bypasses replay; a half-translated event
//!    is never emitted.
//!
//! Raw stored provenance keeps canonical paths and a REDACTED mapping
//! receipt: canonical prefixes travel verbatim (they are host-free by
//! construction), worktree paths travel only as digests — a user's
//! home directory never lands in shared provenance.

use sha2::{Digest, Sha256};

/// The canonical visible namespace marker (rabs-sandbox layout root).
const CANONICAL_MARKER: &str = "/__rabs";

/// One mapping entry: canonical prefix → this subscriber's real path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    /// Canonical virtual prefix (must live under `/__rabs`).
    pub canonical: String,
    /// The requesting worktree's real path for that prefix.
    pub worktree: String,
}

/// Typed refusal from mapping construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// The canonical side is not under the canonical namespace.
    NonCanonicalSource {
        /// The offending prefix.
        canonical: String,
    },
    /// A side is empty.
    EmptyEntry,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalSource { canonical } => {
                write!(
                    f,
                    "mapping source {canonical:?} is not under {CANONICAL_MARKER}"
                )
            }
            Self::EmptyEntry => write!(f, "mapping entries must be non-empty"),
        }
    }
}

impl std::error::Error for MappingError {}

/// A subscriber-specific translation mapping (longest-prefix-first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberMapping {
    entries: Vec<MappingEntry>,
}

/// The provenance-safe receipt: canonical prefixes verbatim, worktree
/// sides as SHA-256 digests only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedMappingReceipt {
    /// (canonical prefix, sha256(worktree path)) pairs.
    pub entries: Vec<(String, [u8; 32])>,
}

impl SubscriberMapping {
    /// Build a mapping; canonical sides must live under `/__rabs`.
    /// Entries apply longest-canonical-prefix first.
    pub fn new(mut entries: Vec<MappingEntry>) -> Result<Self, MappingError> {
        for entry in &entries {
            if entry.canonical.is_empty() || entry.worktree.is_empty() {
                return Err(MappingError::EmptyEntry);
            }
            if !entry.canonical.starts_with(CANONICAL_MARKER) {
                return Err(MappingError::NonCanonicalSource {
                    canonical: entry.canonical.clone(),
                });
            }
        }
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.canonical.len()));
        Ok(Self { entries })
    }

    /// Rewrite every canonical prefix occurrence inside one string.
    fn rewrite_str(&self, value: &str) -> String {
        let mut out = value.to_string();
        for entry in &self.entries {
            out = out.replace(&entry.canonical, &entry.worktree);
        }
        out
    }

    /// The redacted receipt for provenance (no raw worktree paths).
    #[must_use]
    pub fn redacted_receipt(&self) -> RedactedMappingReceipt {
        RedactedMappingReceipt {
            entries: self
                .entries
                .iter()
                .map(|entry| {
                    let mut hasher = Sha256::new();
                    hasher.update(entry.worktree.as_bytes());
                    (entry.canonical.clone(), hasher.finalize().into())
                })
                .collect(),
        }
    }
}

/// Outcome of translating one payload for one subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslationOutcome {
    /// Fully translated — safe to serve this subscriber.
    Translated(String),
    /// rustc artifact-notification: replayed byte-verbatim (the exact
    /// path Cargo requested and is waiting on).
    ReplayedVerbatim(String),
    /// Translation incomplete: canonical markers survived. The caller
    /// must use a presentation variant or bypass replay — this payload
    /// must NOT be served as-is.
    Bypass {
        /// The strings still carrying canonical markers.
        untranslated: Vec<String>,
    },
    /// The payload is not valid JSON (structured surfaces only).
    NotJson,
}

fn collect_untranslated(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            if text.contains(CANONICAL_MARKER) {
                found.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_untranslated(item, found);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_untranslated(item, found);
            }
        }
        _ => {}
    }
}

fn rewrite_value(mapping: &SubscriberMapping, value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if text.contains(CANONICAL_MARKER) {
                *text = mapping.rewrite_str(text);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite_value(mapping, item);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                rewrite_value(mapping, item);
            }
        }
        _ => {}
    }
}

/// Translate one structured compiler event (a single JSON line) for a
/// subscriber. rustc artifact-notifications pass through verbatim;
/// everything else is rewritten and completeness-checked.
#[must_use]
pub fn translate_structured_event(
    mapping: &SubscriberMapping,
    event_json: &str,
) -> TranslationOutcome {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(event_json) else {
        return TranslationOutcome::NotJson;
    };
    // rustc's internal artifact-notification: {"artifact": "<path>", …}.
    // NOT Cargo's outward {"reason": "compiler-artifact"} message — that
    // one is an ordinary translatable payload (and is never synthesized
    // here; we only translate what exists).
    if value.get("artifact").is_some() && value.get("reason").is_none() {
        return TranslationOutcome::ReplayedVerbatim(event_json.to_string());
    }
    rewrite_value(mapping, &mut value);
    let mut untranslated = Vec::new();
    collect_untranslated(&value, &mut untranslated);
    if untranslated.is_empty() {
        TranslationOutcome::Translated(value.to_string())
    } else {
        TranslationOutcome::Bypass { untranslated }
    }
}

/// Translate a RENDERED surface (human diagnostic text, `rch why`
/// output): plain prefix rewriting with the same completeness rule.
#[must_use]
pub fn translate_rendered(mapping: &SubscriberMapping, text: &str) -> TranslationOutcome {
    let rewritten = mapping.rewrite_str(text);
    if rewritten.contains(CANONICAL_MARKER) {
        TranslationOutcome::Bypass {
            untranslated: rewritten
                .lines()
                .filter(|line| line.contains(CANONICAL_MARKER))
                .map(str::to_string)
                .collect(),
        }
    } else {
        TranslationOutcome::Translated(rewritten)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping_for(worktree: &str) -> SubscriberMapping {
        SubscriberMapping::new(vec![
            MappingEntry {
                canonical: "/__rabs/workspace".into(),
                worktree: worktree.into(),
            },
            MappingEntry {
                canonical: "/__rabs/out/fixture".into(),
                worktree: format!("{worktree}/target"),
            },
        ])
        .unwrap()
    }

    const DIAGNOSTIC: &str = r#"{"$message_type":"diagnostic","message":"unused variable","spans":[{"file_name":"/__rabs/workspace/src/lib.rs","line_start":3}],"rendered":"warning: unused variable\n --> /__rabs/workspace/src/lib.rs:3:9\n"}"#;

    #[test]
    fn same_canonical_event_translates_per_subscriber_worktree() {
        // THE two-worktree acceptance fixture: one canonical event, two
        // subscribers, each sees ONLY their own real paths.
        for worktree in ["/home/alice/proj", "/Users/bob/checkout"] {
            let outcome = translate_structured_event(&mapping_for(worktree), DIAGNOSTIC);
            let TranslationOutcome::Translated(out) = outcome else {
                panic!("expected full translation, got {outcome:?}");
            };
            assert!(out.contains(&format!("{worktree}/src/lib.rs")));
            assert!(!out.contains("/__rabs"), "no canonical marker may survive");
        }
    }

    #[test]
    fn artifact_notification_is_replayed_byte_verbatim() {
        let notification =
            r#"{"artifact":"/__rabs/out/fixture/debug/deps/libfx.rmeta","emit":"metadata"}"#;
        let outcome = translate_structured_event(&mapping_for("/home/alice/proj"), notification);
        assert_eq!(
            outcome,
            TranslationOutcome::ReplayedVerbatim(notification.to_string()),
            "the exact path Cargo requested must reach Cargo untouched"
        );
    }

    #[test]
    fn cargo_compiler_artifact_is_translated_not_confused_with_rustc_notification() {
        // Cargo's outward message has "reason" (and may carry paths);
        // it is a translatable payload, never the verbatim-replay one.
        let cargo_msg = r#"{"reason":"compiler-artifact","artifact":"/__rabs/workspace/x","filenames":["/__rabs/out/fixture/debug/fx"]}"#;
        let outcome = translate_structured_event(&mapping_for("/home/alice/proj"), cargo_msg);
        let TranslationOutcome::Translated(out) = outcome else {
            panic!("expected translation, got {outcome:?}");
        };
        assert!(out.contains("/home/alice/proj/target/debug/fx"));
    }

    #[test]
    fn incomplete_translation_bypasses_instead_of_serving_half_rewritten() {
        // A canonical registry path with NO mapping entry: unsafe to
        // translate — typed bypass listing the survivor, never a
        // half-translated event.
        let event = r#"{"$message_type":"diagnostic","spans":[{"file_name":"/__rabs/registry/abc123/serde/src/lib.rs"}],"rendered":"error in /__rabs/registry/abc123/serde/src/lib.rs"}"#;
        let outcome = translate_structured_event(&mapping_for("/home/alice/proj"), event);
        let TranslationOutcome::Bypass { untranslated } = outcome else {
            panic!("expected bypass, got {outcome:?}");
        };
        assert!(
            untranslated
                .iter()
                .all(|survivor| survivor.contains("/__rabs/registry/abc123")),
            "{untranslated:?}"
        );
    }

    #[test]
    fn rendered_and_rch_why_surfaces_translate_with_the_same_rule() {
        let mapping = mapping_for("/home/alice/proj");
        let why = "action cached: inputs /__rabs/workspace/src/lib.rs (+2)\n";
        let TranslationOutcome::Translated(out) = translate_rendered(&mapping, why) else {
            panic!()
        };
        assert_eq!(
            out,
            "action cached: inputs /home/alice/proj/src/lib.rs (+2)\n"
        );
        assert!(matches!(
            translate_rendered(&mapping, "input /__rabs/git/beef00/x.rs"),
            TranslationOutcome::Bypass { .. }
        ));
    }

    #[test]
    fn provenance_receipt_is_redacted() {
        let mapping = mapping_for("/home/alice/secret-project");
        let receipt = mapping.redacted_receipt();
        assert_eq!(receipt.entries.len(), 2);
        for (canonical, digest) in &receipt.entries {
            assert!(
                canonical.starts_with("/__rabs"),
                "canonical travels verbatim"
            );
            assert_ne!(digest, &[0u8; 32]);
        }
        let serialized = format!("{receipt:?}");
        assert!(
            !serialized.contains("alice"),
            "no raw worktree path may appear in provenance: {serialized}"
        );
    }

    #[test]
    fn mapping_construction_refuses_non_canonical_sources() {
        let err = SubscriberMapping::new(vec![MappingEntry {
            canonical: "/home/alice/proj".into(),
            worktree: "/elsewhere".into(),
        }])
        .unwrap_err();
        assert!(matches!(err, MappingError::NonCanonicalSource { .. }));
        assert!(matches!(
            SubscriberMapping::new(vec![MappingEntry {
                canonical: String::new(),
                worktree: "/x".into(),
            }]),
            Err(MappingError::EmptyEntry)
        ));
    }

    #[test]
    fn longest_prefix_wins_so_nested_roots_do_not_shadow() {
        // /__rabs/out/fixture must map via its own entry, not via a
        // shorter /__rabs/out entry that happens to sort first.
        let mapping = SubscriberMapping::new(vec![
            MappingEntry {
                canonical: "/__rabs/out".into(),
                worktree: "/home/alice/generic-out".into(),
            },
            MappingEntry {
                canonical: "/__rabs/out/fixture".into(),
                worktree: "/home/alice/proj/target".into(),
            },
        ])
        .unwrap();
        let TranslationOutcome::Translated(out) =
            translate_rendered(&mapping, "path /__rabs/out/fixture/debug/fx")
        else {
            panic!()
        };
        assert_eq!(out, "path /home/alice/proj/target/debug/fx");
    }
}
