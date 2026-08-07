//! Action/operation/object inspection engines (bead R003; plan
//! §105): `rch rabs action show KEY`, `operation show ID`,
//! `object stat|verify|locate ID`.
//!
//! Three rules govern every report:
//!
//! - BOUNDED: list sections truncate at a fixed bound with the
//!   dropped count RECORDED — output size is capped, and truncation
//!   is never silent;
//! - SCHEMA-STABLE: the textual render is deterministic
//!   `key=value` lines whose shapes are pinned by golden test —
//!   tooling may parse them;
//! - stable reason codes throughout (verification verdicts included).

use crate::action_key::ActionKeyBreakdown;
use crate::typed_digest::compute;
use rabs_protocol::decision_receipt::DecisionReceipt;
use rabs_protocol::result_identity::TypedDigest;

/// Maximum entries any list section renders.
pub const MAX_LIST_ENTRIES: usize = 32;

fn hex8(digest: &TypedDigest) -> String {
    digest.bytes[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A bounded list section: kept entries + dropped count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded<T> {
    /// The entries kept (at most [`MAX_LIST_ENTRIES`]).
    pub entries: Vec<T>,
    /// How many were truncated (0 = complete).
    pub truncated: usize,
}

fn bound<T>(mut items: Vec<T>) -> Bounded<T> {
    let truncated = items.len().saturating_sub(MAX_LIST_ENTRIES);
    items.truncate(MAX_LIST_ENTRIES);
    Bounded {
        entries: items,
        truncated,
    }
}

/// `action show KEY`.
#[must_use]
pub fn action_show(breakdown: &ActionKeyBreakdown) -> Vec<String> {
    let mut lines = vec![
        format!("action.key={}", hex8(&breakdown.final_key)),
        format!("action.key_epoch={}", breakdown.key_epoch),
        format!("action.projection_epoch={}", breakdown.projection_epoch),
        format!("action.class_tag={}", breakdown.action_class_tag),
    ];
    let components = bound(breakdown.components.clone());
    for component in &components.entries {
        lines.push(format!(
            "action.component.{}={}",
            component.name,
            hex8(&component.digest)
        ));
    }
    lines.push(format!(
        "action.components.truncated={}",
        components.truncated
    ));
    lines
}

/// `operation show ID`.
#[must_use]
pub fn operation_show(receipt: &DecisionReceipt) -> Vec<String> {
    let mut lines = vec![
        format!("operation.request_id={}", receipt.request_id),
        format!("operation.cache_lookup={:?}", receipt.cache_lookup),
        format!("operation.singleflight={:?}", receipt.singleflight),
        format!(
            "operation.selected_worker={}",
            receipt
                .selected_worker
                .map_or_else(|| "none".to_owned(), |w| w.to_string())
        ),
        format!("operation.publication={:?}", receipt.publication),
        format!("operation.latency_ms={}", receipt.latency_ms),
    ];
    let events = bound(receipt.lifecycle_events.clone());
    for event in &events.entries {
        lines.push(format!("operation.event.{}={}", event.seq, event.event));
    }
    lines.push(format!("operation.events.truncated={}", events.truncated));
    lines
}

/// Object verification verdict (stable reason codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectVerify {
    /// Bytes recompute to the expected digest.
    Verified,
    /// Bytes do NOT recompute — corruption (the R008 signal).
    Corrupt,
}

/// `object verify ID`: recompute the digest of `bytes` in the id's
/// own domain and compare.
#[must_use]
pub fn object_verify(expected: &TypedDigest, bytes: &[u8]) -> ObjectVerify {
    if compute(expected.domain, bytes).bytes == expected.bytes {
        ObjectVerify::Verified
    } else {
        ObjectVerify::Corrupt
    }
}

/// `object stat ID`.
#[must_use]
pub fn object_stat(digest: &TypedDigest, stored_length: Option<u64>) -> Vec<String> {
    vec![
        format!("object.id={}", hex8(digest)),
        format!("object.domain={}", digest.domain),
        format!("object.present={}", stored_length.is_some()),
        format!(
            "object.length={}",
            stored_length.map_or_else(|| "none".to_owned(), |l| l.to_string())
        ),
    ]
}

/// `object locate ID`: which nodes hold it (bounded).
#[must_use]
pub fn object_locate(digest: &TypedDigest, holders: &[u64]) -> Vec<String> {
    let held = bound(holders.to_vec());
    let mut lines = vec![
        format!("object.id={}", hex8(digest)),
        format!("object.replicas={}", holders.len()),
    ];
    for node in &held.entries {
        lines.push(format!("object.holder={node}"));
    }
    lines.push(format!("object.holders.truncated={}", held.truncated));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_key::BreakdownComponent;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn action_show_render_is_schema_stable() {
        // THE golden: the exact line shapes tooling parses.
        let breakdown = ActionKeyBreakdown {
            key_epoch: 1,
            projection_epoch: 2,
            action_class_tag: 3,
            components: vec![BreakdownComponent {
                name: "toolchain",
                digest: d(0xAB),
            }],
            final_key: d(0xCD),
        };
        assert_eq!(
            action_show(&breakdown),
            vec![
                "action.key=cdcdcdcd",
                "action.key_epoch=1",
                "action.projection_epoch=2",
                "action.class_tag=3",
                "action.component.toolchain=abababab",
                "action.components.truncated=0",
            ]
        );
    }

    #[test]
    fn list_sections_are_bounded_with_truncation_recorded() {
        // 100 components: 32 rendered, 68 recorded truncated —
        // bounded output, never silent truncation.
        let breakdown = ActionKeyBreakdown {
            key_epoch: 1,
            projection_epoch: 1,
            action_class_tag: 1,
            components: (0..100)
                .map(|_| BreakdownComponent {
                    name: "invocation",
                    digest: d(1),
                })
                .collect(),
            final_key: d(2),
        };
        let lines = action_show(&breakdown);
        let component_lines = lines
            .iter()
            .filter(|l| l.starts_with("action.component."))
            .count();
        assert_eq!(component_lines, MAX_LIST_ENTRIES);
        assert!(lines.contains(&"action.components.truncated=68".to_owned()));
    }

    #[test]
    fn object_verify_recomputes_in_the_ids_own_domain() {
        let bytes = b"the artifact bytes";
        let good = compute("rabs.object.v1", bytes);
        assert_eq!(object_verify(&good, bytes), ObjectVerify::Verified);
        // Corruption: one flipped byte.
        let mut corrupted = bytes.to_vec();
        corrupted[0] ^= 0xFF;
        assert_eq!(object_verify(&good, &corrupted), ObjectVerify::Corrupt);
        // Confusion guard: the right bytes under the WRONG domain
        // also fail — verification is domain-separated (T044).
        let wrong_domain = compute("rabs.t044.a", bytes);
        assert_eq!(object_verify(&wrong_domain, bytes), ObjectVerify::Verified);
        let grafted = TypedDigest {
            algorithm: good.algorithm,
            domain: "rabs.t044.a",
            bytes: good.bytes,
        };
        assert_eq!(object_verify(&grafted, bytes), ObjectVerify::Corrupt);
    }

    #[test]
    fn object_stat_and_locate_render_stably() {
        assert_eq!(
            object_stat(&d(0x11), Some(4_096)),
            vec![
                "object.id=11111111",
                "object.domain=rabs.object.v1",
                "object.present=true",
                "object.length=4096",
            ]
        );
        assert_eq!(
            object_stat(&d(0x11), None),
            vec![
                "object.id=11111111",
                "object.domain=rabs.object.v1",
                "object.present=false",
                "object.length=none",
            ]
        );
        let lines = object_locate(&d(0x11), &[5, 9]);
        assert_eq!(
            lines,
            vec![
                "object.id=11111111",
                "object.replicas=2",
                "object.holder=5",
                "object.holder=9",
                "object.holders.truncated=0",
            ]
        );
    }
}
