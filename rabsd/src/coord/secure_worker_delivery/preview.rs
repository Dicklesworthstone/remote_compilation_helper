//! Bounded observation on the execution connection. A preview has no outcome,
//! transcript, durability or publication authority. The transport owner validates
//! the complete reply before passing it to the nonblocking per-job observer.

use super::{invalid, require};
use crate::coord::prepared_operation::PreviewObserver;
use rabs_asupersync::stream_drain::preview::{MAX_PREVIEW_BYTES, OutputPreview, PreviewStream};
use serde_json::{Value, json};
use std::io;
use std::time::{Duration, Instant};

pub(super) const VERSION: &str = "tail-v1";
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Default)]
struct Cursors {
    ends: [u64; 2],
    observed: [u64; 2],
}

impl Cursors {
    fn decode(&mut self, frame: &Value, request_id: u64) -> io::Result<(bool, Vec<OutputPreview>)> {
        require(
            frame.as_object().is_some_and(|fields| fields.len() == 7)
                && frame["kind"] == "output-preview"
                && frame["version"] == VERSION
                && frame["request_id"].as_u64() == Some(request_id)
                && frame["active"].as_bool().is_some()
                && frame["complete"] == false
                && frame["publication_authorized"] == false,
            "invalid or foreign output preview",
        )?;
        let rows = frame["segments"]
            .as_array()
            .filter(|rows| rows.len() <= 2)
            .ok_or_else(|| invalid("unbounded preview segment list"))?;
        let active = frame["active"] == true;
        require(
            active || rows.is_empty(),
            "inactive preview cannot supply output bytes",
        )?;
        let mut seen = [false; 2];
        let mut ends = self.ends;
        let mut observed = self.observed;
        let mut segments = Vec::with_capacity(rows.len());
        for row in rows {
            require(
                row.as_object().is_some_and(|fields| fields.len() == 5),
                "invalid preview segment fields",
            )?;
            let (index, stream) = match row["stream"].as_str() {
                Some("stdout") => (0, PreviewStream::Stdout),
                Some("stderr") => (1, PreviewStream::Stderr),
                _ => return Err(invalid("unknown preview stream")),
            };
            require(!seen[index], "duplicate preview stream")?;
            seen[index] = true;
            let number = |name: &str| {
                row[name]
                    .as_u64()
                    .ok_or_else(|| invalid(format!("invalid preview {name}")))
            };
            let offset = number("offset")?;
            let skipped_bytes = number("skipped_bytes")?;
            let observed_bytes = number("observed_bytes")?;
            let encoded = row["data_hex"]
                .as_str()
                .filter(|text| {
                    text.len() <= MAX_PREVIEW_BYTES * 2
                        && text.len().is_multiple_of(2)
                        && text
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| invalid("invalid or unbounded preview bytes"))?;
            let end = offset
                .checked_add((encoded.len() / 2) as u64)
                .ok_or_else(|| invalid("preview offset overflow"))?;
            require(
                offset.checked_sub(ends[index]) == Some(skipped_bytes)
                    && end > ends[index]
                    && observed_bytes >= end
                    && observed_bytes >= observed[index],
                "rewound or inconsistent preview offsets",
            )?;
            let mut bytes = Vec::with_capacity(encoded.len() / 2);
            for pair in encoded.as_bytes().as_chunks::<2>().0 {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'a' + 10
                    }
                };
                bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
            }
            segments.push(OutputPreview {
                stream,
                offset,
                bytes,
                skipped_bytes,
                observed_bytes,
            });
            ends[index] = end;
            observed[index] = observed_bytes;
        }
        // An invalid second stream must not advance the first stream's cursor.
        self.ends = ends;
        self.observed = observed;
        Ok((active, segments))
    }
}

pub(super) struct PreviewSession {
    observer: PreviewObserver,
    selected: bool,
    request: Option<u64>,
    next_poll: Option<Instant>,
    pending: bool,
    stopped: bool,
    cursors: Cursors,
}

impl PreviewSession {
    pub(super) fn new(observer: PreviewObserver) -> Self {
        Self {
            observer,
            selected: false,
            request: None,
            next_poll: None,
            pending: false,
            stopped: false,
            cursors: Cursors::default(),
        }
    }

    pub(super) fn select(&mut self, grant: &Value) -> io::Result<()> {
        require(
            self.request.is_none() && !self.selected,
            "preview cannot be renegotiated",
        )?;
        match grant.get("output_preview") {
            None => Ok(()),
            Some(value) if value == VERSION => {
                self.selected = true;
                Ok(())
            }
            Some(_) => Err(invalid("unsupported output preview selection")),
        }
    }

    pub(super) fn arm(&mut self, request_id: u64) {
        self.request = Some(request_id);
        if self.selected {
            self.next_poll = Some(Instant::now());
        }
    }

    pub(super) fn wake_at(&self) -> Option<Instant> {
        if self.pending || self.stopped {
            None
        } else {
            self.next_poll
        }
    }

    pub(super) fn query(&mut self, now: Instant) -> Option<Value> {
        if self.wake_at().is_none_or(|at| now < at) {
            return None;
        }
        let request_id = self.request?;
        self.pending = true; // burn before any possibly partial write
        self.next_poll = None;
        Some(json!({"kind":"output-preview", "request_id":request_id}))
    }

    pub(super) fn consume(&mut self, frame: &Value) -> io::Result<()> {
        require(
            self.pending,
            "unsolicited or duplicate output preview reply",
        )?;
        let request = self
            .request
            .ok_or_else(|| invalid("preview before execution"))?;
        let (active, segments) = self.cursors.decode(frame, request)?;
        self.pending = false;
        if self.stopped {
            return Ok(());
        }
        // This fixed implementation only touches its separate bounded in-memory
        // cache using try_lock; it cannot wait on disk, a CLI, or the job store.
        let _ = self.observer.observe(active, &segments);
        if active {
            self.next_poll = Some(Instant::now() + POLL_INTERVAL);
        } else {
            self.stop();
        }
        Ok(())
    }

    pub(super) fn stop(&mut self) {
        self.stopped = true;
        self.next_poll = None;
        // Preserve only the one outstanding reply's correlation, for a terminal
        // result that overtakes it. No query may be sent after this frontier.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(stream: &str, offset: u64, data: &str, skipped: u64, observed: u64) -> Value {
        json!({"stream":stream,"offset":offset,"data_hex":data,
            "skipped_bytes":skipped,"observed_bytes":observed})
    }
    fn reply(segments: Vec<Value>) -> Value {
        json!({"kind":"output-preview","version":VERSION,"request_id":0,
            "active":true,"segments":segments,"complete":false,"publication_authorized":false})
    }

    #[test]
    fn independent_binary_cursors_keep_gaps_and_observed_lengths_distinct() {
        let mut cursors = Cursors::default();
        let (_, segments) = cursors
            .decode(
                &reply(vec![
                    segment("stdout", 3, "00ff", 3, 10),
                    segment("stderr", 0, "e99baa", 0, 3),
                ]),
                0,
            )
            .unwrap();
        assert_eq!(segments[0].bytes, b"\0\xff");
        assert_eq!(segments[1].bytes, "雪".as_bytes());
        assert_eq!(cursors.ends, [5, 3]);
        let (_, gap) = cursors
            .decode(&reply(vec![segment("stdout", 10, "", 5, 10)]), 0)
            .unwrap();
        assert!(gap[0].bytes.is_empty());
        assert_eq!(gap[0].skipped_bytes, 5);
        assert_eq!(cursors.ends, [10, 3]);
        cursors
            .decode(&reply(vec![segment("stdout", 10, "61", 0, 11)]), 0)
            .unwrap();
        assert_eq!(cursors.ends, [11, 3]);
    }

    #[test]
    fn invalid_second_stream_never_partially_advances_observation() {
        let mut cursors = Cursors::default();
        let first = segment("stdout", 0, "ff", 0, 1);
        for bad in [
            segment("stderr", 0, "Ff", 0, 1),
            segment("stdout", 1, "aa", 0, 2),
            segment("stderr", 0, "a", 0, 1),
            segment("stderr", 0, "ff", 1, 1),
            segment("stderr", u64::MAX, "ff", u64::MAX, u64::MAX),
            segment("stderr", 0, &"ff".repeat(MAX_PREVIEW_BYTES + 1), 0, 8193),
        ] {
            assert!(cursors.decode(&reply(vec![first.clone(), bad]), 0).is_err());
            assert_eq!(cursors.ends, [0, 0]);
            assert_eq!(cursors.observed, [0, 0]);
        }
        cursors.decode(&reply(vec![first.clone()]), 0).unwrap();
        assert!(
            cursors.decode(&reply(vec![first]), 0).is_err(),
            "replay cannot rewind a tail"
        );
    }

    #[test]
    fn previews_never_claim_completion_publication_or_another_request() {
        for (field, value) in [
            ("request_id", json!(1)),
            ("complete", json!(true)),
            ("publication_authorized", json!(true)),
            ("version", json!("unknown")),
            ("exit_code", json!(0)),
            ("active", Value::Null),
        ] {
            let mut frame = reply(Vec::new());
            frame[field] = value;
            assert!(Cursors::default().decode(&frame, 0).is_err(), "{field}");
        }
        let mut inactive = reply(vec![segment("stdout", 0, "ff", 0, 1)]);
        inactive["active"] = json!(false);
        assert!(Cursors::default().decode(&inactive, 0).is_err());
        inactive["segments"] = json!([]);
        assert!(!Cursors::default().decode(&inactive, 0).unwrap().0);
    }
}
