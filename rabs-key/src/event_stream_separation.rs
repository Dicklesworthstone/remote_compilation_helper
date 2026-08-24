//! rustc artifact-notification vs Cargo outward-message stream
//! separation (bead K013; plan Epic K/m4; feeds K005's never-synthesize
//! replay rule).
//!
//! Two DIFFERENT producers emit JSON lines during one build:
//!
//! - **rustc artifact notifications** — the nightly-only
//!   `--json=artifacts` channel; lines are objects whose discriminator
//!   is `"$message_type":"artifact"` plus an `"artifact"` path;
//! - **Cargo outward messages** — `cargo --message-format=json`; every
//!   line is an object with a top-level `"reason"` string
//!   (`compiler-artifact`, `compiler-message`, `build-finished`, ...).
//!
//! A parser that conflates them misattributes events silently — the
//! worst failure mode, because a swapped stream looks like healthy
//! traffic. This module owns the separation:
//!
//! - [`classify_line`] tags each line by its DISCRIMINATOR (the
//!   `$message_type` field for rustc notifications, the `reason` field
//!   for Cargo outward messages), refusing anything that has neither,
//!   both, or does not parse — loudly, as [`LineClass::Unclassified`];
//! - GOLDEN FIXTURES captured from real toolchains pin BOTH streams
//!   separately per channel ([`GOLDEN_FIXTURES`]). An upstream
//!   vocabulary change (a renamed reason, a moved discriminator)
//!   surfaces as a compatibility-matrix failure naming the exact
//!   channel+stream cell — never as a silent misparse;
//! - stable/beta REFUSE the artifact channel outright (`-Z` gate);
//!   those refusals are fixtures too: an unexpected "success" on a
//!   refusal channel is a matrix failure.
//!
//! The production scanner is a minimal top-level key reader (no JSON
//! dependency in this crate per the A002 charter); the test module
//! cross-checks it against `serde_json` on every golden line.
//!
//! Capture provenance: all goldens were captured 2026-08-24 from the
//! installed rustup toolchains against a two-line hello-lib workspace,
//! executed locally. Absolute paths are replaced with `<WS>`/`<TARGET>`
//! placeholders; everything else is verbatim bytes.

/// Which producer a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStream {
    /// rustc `--json=artifacts` notification (`$message_type`
    /// discriminator).
    RustcArtifactNotification,
    /// Cargo `--message-format=json` outward message (`reason`
    /// discriminator).
    CargoOutwardMessage,
}

/// Toolchain channel of a fixture cell (K013 acceptance spans them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    Nightly,
}

/// Classification outcome for one observed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineClass {
    /// rustc artifact notification; carries the `$message_type` value.
    RustcArtifact {
        /// Discriminator value (currently always `artifact`).
        message_type: String,
    },
    /// Cargo outward message; carries its `reason`.
    CargoOutward {
        /// The reason string (compiler-artifact, build-finished, ...).
        reason: String,
    },
    /// Neither producer, both at once, or unparseable: a loud refusal
    /// that upstream callers MUST surface as a compatibility failure —
    /// never drop on the floor.
    Unclassified {
        /// Why the line refused classification.
        why: &'static str,
    },
}

impl LineClass {
    /// Which stream this line belongs to, if any.
    #[must_use]
    pub fn stream(&self) -> Option<EventStream> {
        match self {
            Self::RustcArtifact { .. } => Some(EventStream::RustcArtifactNotification),
            Self::CargoOutward { .. } => Some(EventStream::CargoOutwardMessage),
            Self::Unclassified { .. } => None,
        }
    }
}

/// Classify one line of compiler/cargo JSON output by its top-level
/// discriminator. Only the FIRST JSON object on the line is examined;
/// both producers emit exactly one object per line.
#[must_use]
pub fn classify_line(line: &str) -> LineClass {
    let Some(disc) = scan_top_level_discriminators(line) else {
        return LineClass::Unclassified {
            why: "not-a-json-object",
        };
    };
    let has_artifact_field = top_level_key_present(line, "artifact");
    match (disc.message_type.as_deref(), disc.reason.as_deref()) {
        // BOTH discriminators: ambiguous provenance, refuses loudly —
        // this is the shape a future toolchain regression would produce.
        (Some(_), Some(_)) => LineClass::Unclassified {
            why: "both-discriminators-present",
        },
        (Some(mt), None) => LineClass::RustcArtifact {
            message_type: mt.to_owned(),
        },
        (None, Some(_)) if has_artifact_field => LineClass::Unclassified {
            why: "reason-plus-artifact-field",
        },
        (None, Some(reason)) => LineClass::CargoOutward {
            reason: reason.to_owned(),
        },
        _ => LineClass::Unclassified {
            why: "no-discriminator",
        },
    }
}

struct ScannedDiscriminators {
    message_type: Option<String>,
    reason: Option<String>,
}

/// Minimal scanner: one pass over the line, tracking string context and
/// container depth, capturing ONLY top-level `"reason"` /
/// `"$message_type"` values. Not a general JSON parser — its contract
/// is limited to single-line objects emitted by our two producers, and
/// the test suite cross-checks it against serde_json on every golden.
fn scan_top_level_discriminators(line: &str) -> Option<ScannedDiscriminators> {
    let bytes = line.as_bytes();
    let trimmed = line.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return None;
    }
    let mut message_type = None;
    let mut reason = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                // A top-level key: try the whole-span reader first; it
                // consumes through the value's closing quote and leaves
                // string-state untouched (setting in_string here would
                // desync the state machine after the first pair).
                if depth == 1
                    && let Some((key, value, next)) = read_key_and_string_value(bytes, i)
                {
                    match key {
                        "$message_type" => message_type = value,
                        "reason" => reason = value,
                        _ => {}
                    }
                    i = next;
                    continue;
                }
                in_string = true;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    Some(ScannedDiscriminators {
        message_type,
        reason,
    })
}

/// At `open_quote` (a `"` opening a top-level key), attempt to read
/// `"key" : "value"`. Returns `(key, value, index_after_closing_quote)`
/// when the shape matches; non-string or missing values yield `None`.
fn read_key_and_string_value(
    bytes: &[u8],
    open_quote: usize,
) -> Option<(&str, Option<String>, usize)> {
    let mut j = open_quote + 1;
    while j < bytes.len() && bytes[j] != b'"' {
        if bytes[j] == b'\\' {
            j += 1; // skip escaped char inside the key
        }
        j += 1;
    }
    if j >= bytes.len() {
        return None;
    }
    let key = core::str::from_utf8(&bytes[open_quote + 1..j]).ok()?;
    let mut k = j + 1;
    while k < bytes.len() && (bytes[k] == b':' || bytes[k].is_ascii_whitespace()) {
        k += 1;
    }
    if k >= bytes.len() || bytes[k] != b'"' {
        return None; // not a string value (number/bool/object/array/null)
    }
    k += 1;
    let mut value = String::new();
    while k < bytes.len() && bytes[k] != b'"' {
        if bytes[k] == b'\\' && k + 1 < bytes.len() {
            k += 2;
            value.push('?'); // escape sequences are irrelevant to identity here
            continue;
        }
        if bytes[k].is_ascii() {
            value.push(bytes[k] as char);
        } else {
            value.push('?');
        }
        k += 1;
    }
    if k >= bytes.len() {
        return None;
    }
    Some((key, Some(value), k + 1))
}

/// Whether `key` appears as a TOP-LEVEL object key (used to detect the
/// ambiguous both-fields case).
fn top_level_key_present(line: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    let bytes = line.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'"' {
                in_string = false;
            } else if b == b'\\' {
                i += 1;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }
            if depth == 1 && line[i..].starts_with(&needle) {
                let mut j = i + needle.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------
// Golden fixtures — captured 2026-08-24 from installed toolchains.
// ---------------------------------------------------------------------

/// One pinned cell: a channel/stream pair and its EXACT captured lines.
/// Stable/beta artifact cells are EMPTY with the pinned refusal prefix:
/// their compatibility fact IS the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenCell {
    /// Toolchain channel this capture came from.
    pub channel: Channel,
    /// Which stream this cell pins.
    pub stream: EventStream,
    /// Captured stdout lines (`<WS>`/`<TARGET>` placeholders where the
    /// capture machine's absolute paths appeared).
    pub lines: &'static [&'static str],
    /// For refusal channels: the pinned stderr prefix proving the gate.
    pub refusal_stderr_prefix: Option<&'static str>,
}

const ARTIFACT_REFUSAL_STABLE_BETA: &str =
    "error: the option `Z` is only accepted on the nightly compiler";

/// The full matrix: every cell must classify cleanly and stay
/// byte-stable (tests below).
pub const GOLDEN_FIXTURES: &[GoldenCell] = &[
    // ---- Stream A: rustc artifact notifications -------------------
    GoldenCell {
        channel: Channel::Stable,
        stream: EventStream::RustcArtifactNotification,
        lines: &[],
        refusal_stderr_prefix: Some(ARTIFACT_REFUSAL_STABLE_BETA),
    },
    GoldenCell {
        channel: Channel::Beta,
        stream: EventStream::RustcArtifactNotification,
        lines: &[],
        refusal_stderr_prefix: Some(ARTIFACT_REFUSAL_STABLE_BETA),
    },
    GoldenCell {
        channel: Channel::Nightly,
        stream: EventStream::RustcArtifactNotification,
        lines: &[
            "{\"$message_type\":\"artifact\",\"artifact\":\"liblib.rmeta\",\"emit\":\"metadata\"}",
        ],
        refusal_stderr_prefix: None,
    },
    // ---- Stream B: Cargo outward messages --------------------------
    GoldenCell {
        channel: Channel::Stable,
        stream: EventStream::CargoOutwardMessage,
        lines: &[
            "{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file://<WS>#k13@0.1.0\",\"manifest_path\":\"<WS>/Cargo.toml\",\"target\":{\"kind\":[\"lib\"],\"crate_types\":[\"lib\"],\"name\":\"k13\",\"src_path\":\"<WS>/src/lib.rs\",\"edition\":\"2021\",\"doc\":true,\"doctest\":true,\"test\":true},\"profile\":{\"opt_level\":\"0\",\"debuginfo\":2,\"debug_assertions\":true,\"overflow_checks\":true,\"test\":false},\"features\":[],\"filenames\":[\"<TARGET>/debug/libk13.rlib\",\"<TARGET>/debug/deps/libk13-7435e442317756fa.rmeta\"],\"executable\":null,\"fresh\":false}",
            "{\"reason\":\"build-finished\",\"success\":true}",
        ],
        refusal_stderr_prefix: None,
    },
    GoldenCell {
        channel: Channel::Beta,
        stream: EventStream::CargoOutwardMessage,
        lines: &[
            "{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file://<WS>#k13@0.1.0\",\"manifest_path\":\"<WS>/Cargo.toml\",\"target\":{\"kind\":[\"lib\"],\"crate_types\":[\"lib\"],\"name\":\"k13\",\"src_path\":\"<WS>/src/lib.rs\",\"edition\":\"2021\",\"doc\":true,\"doctest\":true,\"test\":true},\"profile\":{\"opt_level\":\"0\",\"debuginfo\":2,\"debug_assertions\":true,\"overflow_checks\":true,\"test\":false},\"features\":[],\"filenames\":[\"<TARGET>/debug/libk13.rlib\",\"<TARGET>/debug/deps/libk13-ccea55b954414d6a.rmeta\"],\"executable\":null,\"fresh\":false}",
            "{\"reason\":\"build-finished\",\"success\":true}",
        ],
        refusal_stderr_prefix: None,
    },
    GoldenCell {
        channel: Channel::Nightly,
        stream: EventStream::CargoOutwardMessage,
        lines: &[
            "{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file://<WS>#k13@0.1.0\",\"manifest_path\":\"<WS>/Cargo.toml\",\"target\":{\"kind\":[\"lib\"],\"crate_types\":[\"lib\"],\"name\":\"k13\",\"src_path\":\"<WS>/src/lib.rs\",\"edition\":\"2021\",\"doc\":true,\"doctest\":true,\"test\":true},\"profile\":{\"opt_level\":\"0\",\"debuginfo\":2,\"debug_assertions\":true,\"overflow_checks\":true,\"test\":false},\"features\":[],\"filenames\":[\"<TARGET>/debug/libk13.rlib\",\"<TARGET>/debug/build/k13/fe518474b511d51b/out/libk13-fe518474b511d51b.rmeta\"],\"executable\":null,\"fresh\":false}",
            "{\"reason\":\"build-finished\",\"success\":true}",
        ],
        refusal_stderr_prefix: None,
    },
];

/// Look up the golden cell for a channel/stream pair.
#[must_use]
pub fn golden_cell(channel: Channel, stream: EventStream) -> Option<&'static GoldenCell> {
    GOLDEN_FIXTURES
        .iter()
        .find(|c| c.channel == channel && c.stream == stream)
}

// ---------------------------------------------------------------------
// Tests — K013 acceptance: both streams pinned separately across
// stable/beta/nightly; drift fails LOUDLY with the cell named.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_outward_goldens_classify_with_expected_reasons() {
        for (channel, expected_reasons) in [
            (Channel::Stable, vec!["compiler-artifact", "build-finished"]),
            (Channel::Beta, vec!["compiler-artifact", "build-finished"]),
            (
                Channel::Nightly,
                vec!["compiler-artifact", "build-finished"],
            ),
        ] {
            let cell = golden_cell(channel, EventStream::CargoOutwardMessage).expect("cell exists");
            let reasons: Vec<String> = cell
                .lines
                .iter()
                .map(|l| match classify_line(l) {
                    LineClass::CargoOutward { reason } => reason,
                    other => panic!("{channel:?} line misclassified: {other:?}"),
                })
                .collect();
            assert_eq!(
                reasons, expected_reasons,
                "{channel:?} outward vocabulary drifted"
            );
        }
    }

    #[test]
    fn nightly_artifact_notification_classifies_and_refusals_are_pinned() {
        let night =
            golden_cell(Channel::Nightly, EventStream::RustcArtifactNotification).expect("cell");
        assert_eq!(night.lines.len(), 1);
        assert!(matches!(
            classify_line(night.lines[0]),
            LineClass::RustcArtifact { ref message_type }
                if message_type == "artifact"
        ));
        // Stable/beta refuse the unstable option: the refusal itself is
        // the pinned fact.
        for channel in [Channel::Stable, Channel::Beta] {
            let cell = golden_cell(channel, EventStream::RustcArtifactNotification).expect("cell");
            assert_eq!(
                cell.lines.len(),
                0,
                "{channel:?} must not produce artifact lines"
            );
            assert_eq!(
                cell.refusal_stderr_prefix,
                Some(ARTIFACT_REFUSAL_STABLE_BETA)
            );
        }
    }

    #[test]
    fn cross_stream_confusion_is_impossible_on_goldens() {
        // Every golden line classifies to ITS OWN stream and no other:
        // the separation invariant over the whole matrix.
        for cell in GOLDEN_FIXTURES {
            for line in cell.lines {
                let class = classify_line(line);
                assert_eq!(
                    class.stream(),
                    Some(cell.stream),
                    "{:?}/{:?} line crossed streams: {line}",
                    cell.channel,
                    cell.stream
                );
            }
        }
    }

    #[test]
    fn adversarial_lines_refuse_loudly() {
        // Both discriminators: ambiguous, refuses rather than guesses.
        let both = r#"{"$message_type":"artifact","reason":"compiler-artifact","artifact":"x"}"#;
        assert_eq!(
            classify_line(both),
            LineClass::Unclassified {
                why: "both-discriminators-present"
            }
        );
        // No discriminator.
        assert!(matches!(
            classify_line(r#"{"hello":"world"}"#),
            LineClass::Unclassified { .. }
        ));
        // Not an object / garbage.
        assert_eq!(
            classify_line("plain text"),
            LineClass::Unclassified {
                why: "not-a-json-object"
            }
        );
    }

    #[test]
    fn scanner_agrees_with_real_json_parser_on_every_golden() {
        // Cross-check the dependency-free scanner against serde_json:
        // the scanner's verdict must agree with what a real parser sees
        // at the top level of every golden line.
        for cell in GOLDEN_FIXTURES {
            for line in cell.lines {
                let v: serde_json::Value =
                    serde_json::from_str(line).expect("golden lines are valid JSON");
                let class = classify_line(line);
                if v.get("$message_type").is_some() {
                    assert!(matches!(class, LineClass::RustcArtifact { .. }), "{line}");
                } else if v.get("reason").is_some() {
                    assert!(matches!(class, LineClass::CargoOutward { .. }), "{line}");
                } else {
                    assert!(matches!(class, LineClass::Unclassified { .. }), "{line}");
                }
            }
        }
    }

    #[test]
    fn nested_reason_fields_do_not_leak_into_top_level_verdict() {
        // A cargo compiler-message WRAPPING nested diagnostic content:
        // only the outer "reason" counts; nested lookalikes must not
        // flip the classification.
        let wrapped = r#"{"reason":"compiler-message","message":{"level":"warning","rendered":"x\n"},"target":{}}"#;
        assert_eq!(
            classify_line(wrapped),
            LineClass::CargoOutward {
                reason: "compiler-message".to_owned()
            }
        );
        // And a rustc artifact line whose PATH mentions "reason" text
        // inside a string value still classifies by $message_type.
        let tricky =
            r#"{"$message_type":"artifact","artifact":"/x/reason:/y.rmeta","emit":"metadata"}"#;
        assert!(matches!(
            classify_line(tricky),
            LineClass::RustcArtifact { .. }
        ));
    }
}
