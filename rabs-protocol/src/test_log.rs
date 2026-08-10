//! Test-harness structured-logging standard (bead T053; feeds R001
//! decision receipts and T012 trace minimization).
//!
//! A suite that only prints `ok`/`FAILED` cannot feed shadow reports,
//! divergence corpora, or proof artifacts: the verification program
//! needs machine-readable EVIDENCE. Every RABS suite therefore emits
//! JSON-line records with:
//!
//! - a **causal trace ID** shared by all records of one test;
//! - **attribution** matching the G001 tracing contract
//!   (region/authority/operation/generation/action/attempt);
//! - **per-step timings** (elapsed µs from test start);
//! - the **seed** for deterministic replays;
//! - a terminal **outcome** record whose pass/fail carries evidence
//!   text, so a green checkmark is backed by what was proven.
//!
//! Redaction is built into the emission path: env-shaped fields go
//! through the A007 classifier, path fields through home-redaction,
//! and every free-text field is bounded — a secret or user path
//! cannot reach a test log through this API. The crate is
//! dependency-free, so the JSON encoder is hand-rolled here and
//! covered by escaping tests.
//!
//! The standard document lives at `docs/rabs-test-log-standard.md`;
//! [`TEST_LOG_STANDARD_VERSION`] pins the record format.

use std::collections::BTreeMap;
use std::io::Write;

/// The record-format version (`v` field of every record).
pub const TEST_LOG_STANDARD_VERSION: u32 = 1;

/// Causal attribution per the G001 tracing contract (absent facets are
/// simply omitted from the record).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CausalAttribution {
    /// Owning region/component.
    pub region: Option<String>,
    /// Authority role (edge/coord/worker).
    pub authority: Option<String>,
    /// Operation ID.
    pub operation: Option<String>,
    /// Sealed generation (D032).
    pub generation: Option<u32>,
    /// Action ID.
    pub action: Option<String>,
    /// Attempt ordinal.
    pub attempt: Option<u32>,
}

/// Terminal outcome of one test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    /// Passed, with the evidence that proves it.
    Pass {
        /// What was actually proven (not just "it ran").
        evidence: String,
    },
    /// Failed, with the evidence for the failure.
    Fail {
        /// The failure evidence.
        evidence: String,
    },
}

/// Escape a string for JSON emission.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A JSON-line test logger for one test: emits records to any writer
/// (a file per suite in CI; stderr locally).
pub struct TestLogger<W: Write> {
    sink: W,
    suite: String,
    test: String,
    trace_id: String,
    seed: Option<u64>,
    attribution: CausalAttribution,
    started: std::time::Instant,
}

impl<W: Write> TestLogger<W> {
    /// Start logging one test. The trace ID must be unique per test
    /// run (callers typically derive it from suite/test/seed).
    pub fn start(
        sink: W,
        suite: &str,
        test: &str,
        trace_id: &str,
        seed: Option<u64>,
        attribution: CausalAttribution,
    ) -> std::io::Result<Self> {
        let mut logger = Self {
            sink,
            suite: suite.to_string(),
            test: test.to_string(),
            trace_id: trace_id.to_string(),
            seed,
            attribution,
            started: std::time::Instant::now(),
        };
        logger.emit("start", &BTreeMap::new())?;
        Ok(logger)
    }

    fn emit(&mut self, step: &str, fields: &BTreeMap<String, String>) -> std::io::Result<()> {
        let mut line = String::new();
        line.push_str(&format!(
            "{{\"v\":{},\"suite\":\"{}\",\"test\":\"{}\",\"trace\":\"{}\",\"step\":\"{}\",\"elapsed_us\":{}",
            TEST_LOG_STANDARD_VERSION,
            json_escape(&self.suite),
            json_escape(&self.test),
            json_escape(&self.trace_id),
            json_escape(step),
            self.started.elapsed().as_micros(),
        ));
        if let Some(seed) = self.seed {
            line.push_str(&format!(",\"seed\":{seed}"));
        }
        let attribution = [
            ("region", self.attribution.region.clone()),
            ("authority", self.attribution.authority.clone()),
            ("operation", self.attribution.operation.clone()),
            ("action", self.attribution.action.clone()),
            (
                "generation",
                self.attribution.generation.map(|g| g.to_string()),
            ),
            ("attempt", self.attribution.attempt.map(|a| a.to_string())),
        ];
        for (key, value) in attribution {
            if let Some(value) = value {
                line.push_str(&format!(",\"{key}\":\"{}\"", json_escape(&value)));
            }
        }
        for (key, value) in fields {
            line.push_str(&format!(
                ",\"{}\":\"{}\"",
                json_escape(key),
                json_escape(value)
            ));
        }
        line.push('}');
        writeln!(self.sink, "{line}")
    }

    /// Log one step with free-text fields (each bounded; callers with
    /// env- or path-shaped data use the dedicated methods below).
    pub fn step(&mut self, step: &str, fields: &[(&str, &str)]) -> std::io::Result<()> {
        let bounded: BTreeMap<String, String> = fields
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    crate::redaction::bounded_excerpt(value, 2048),
                )
            })
            .collect();
        self.emit(step, &bounded)
    }

    /// Log an env-shaped observation through the A007 classifier — a
    /// secret-class value is redacted before it can reach the log.
    pub fn env_field(&mut self, step: &str, name: &str, value: &str) -> std::io::Result<()> {
        let mut fields = BTreeMap::new();
        fields.insert(
            format!("env.{name}"),
            crate::redaction::redact_env(name, value),
        );
        self.emit(step, &fields)
    }

    /// Log a path observation with the user home redacted.
    pub fn path_field(
        &mut self,
        step: &str,
        key: &str,
        path: &str,
        home: &str,
    ) -> std::io::Result<()> {
        let mut fields = BTreeMap::new();
        fields.insert(key.to_string(), crate::redaction::redact_path(path, home));
        self.emit(step, &fields)
    }

    /// Emit the terminal outcome record and flush.
    pub fn finish(mut self, outcome: &TestOutcome) -> std::io::Result<()> {
        let mut fields = BTreeMap::new();
        let (verdict, evidence) = match outcome {
            TestOutcome::Pass { evidence } => ("pass", evidence),
            TestOutcome::Fail { evidence } => ("fail", evidence),
        };
        fields.insert("outcome".to_string(), verdict.to_string());
        fields.insert(
            "evidence".to_string(),
            crate::redaction::bounded_excerpt(evidence, 4096),
        );
        self.emit("finish", &fields)?;
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger_into(buffer: &mut Vec<u8>) -> TestLogger<&mut Vec<u8>> {
        TestLogger::start(
            buffer,
            "unit/snapshot",
            "mutation_retry",
            "trace-42",
            Some(42),
            CausalAttribution {
                region: Some("edge".into()),
                operation: Some("op-7".into()),
                generation: Some(2),
                attempt: Some(1),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn records_are_json_lines_with_trace_seed_attribution_and_timing() {
        let mut buffer = Vec::new();
        let mut logger = logger_into(&mut buffer);
        logger.step("scan", &[("files", "12")]).unwrap();
        logger
            .finish(&TestOutcome::Pass {
                evidence: "retry forced; manifest == post-mutation world".into(),
            })
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "start + step + finish");
        for line in &lines {
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
            assert!(line.contains("\"v\":1"));
            assert!(line.contains("\"trace\":\"trace-42\""));
            assert!(line.contains("\"seed\":42"));
            assert!(line.contains("\"elapsed_us\":"));
            assert!(line.contains("\"region\":\"edge\""));
            assert!(line.contains("\"generation\":\"2\""));
        }
        assert!(lines[1].contains("\"files\":\"12\""));
        assert!(lines[2].contains("\"outcome\":\"pass\""));
        assert!(lines[2].contains("retry forced"));
    }

    #[test]
    fn secrets_and_home_paths_cannot_reach_the_log() {
        let mut buffer = Vec::new();
        let mut logger = logger_into(&mut buffer);
        logger
            .env_field(
                "observe-env",
                "AWS_SECRET_ACCESS_KEY",
                "hunter2-actual-secret",
            )
            .unwrap();
        logger
            .path_field(
                "observe-path",
                "workspace",
                "/home/alice/secret-proj/src",
                "/home/alice",
            )
            .unwrap();
        logger
            .finish(&TestOutcome::Fail {
                evidence: "expected redaction".into(),
            })
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            !text.contains("hunter2-actual-secret"),
            "secret value leaked into test log:\n{text}"
        );
        assert!(
            !text.contains("/home/alice"),
            "user home leaked into test log:\n{text}"
        );
        assert!(text.contains("\"outcome\":\"fail\""));
    }

    #[test]
    fn json_escaping_survives_hostile_field_content() {
        let mut buffer = Vec::new();
        let mut logger = logger_into(&mut buffer);
        logger
            .step(
                "hostile",
                &[("payload", "quote\" backslash\\ newline\n tab\t bell\u{7}")],
            )
            .unwrap();
        logger
            .finish(&TestOutcome::Pass {
                evidence: "escaped".into(),
            })
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        let hostile_line = text.lines().nth(1).unwrap();
        assert!(hostile_line.contains(r#"quote\" backslash\\ newline\n tab\t bell"#));
        // Still one record per line: no raw newline broke the framing.
        assert_eq!(text.lines().count(), 3);
    }
}
