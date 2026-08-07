//! Build-script directive capture (bead E015; plan §73; risk R15).
//!
//! A build script speaks to Cargo through `cargo:` lines on stdout.
//! Those lines are SEMANTIC OUTPUT: `rustc-cfg`/`rustc-link-lib`/…
//! reshape downstream compiles, and `rerun-if-changed`/
//! `rerun-if-env-changed` declare the script's own input closure. This
//! parser captures every directive into structured evidence that:
//!
//! - **round-trips byte-exact** — the original line is retained beside
//!   the parse, so replay validation can compare the exact bytes the
//!   script emitted (a re-serialization "close enough" is not
//!   evidence);
//! - feeds keys: `rerun-if-changed` paths and `rerun-if-env-changed`
//!   variables JOIN the observed closure (E010 positive/negative sets
//!   and the F006 environment respectively);
//! - is total: unknown `cargo:` keys are captured as
//!   [`Directive::Metadata`] (the `cargo:KEY=VALUE` form Cargo passes
//!   to dependents — semantic by definition), and non-directive stdout
//!   is preserved as transcript, never dropped.
//!
//! Both `cargo:` and the newer `cargo::` prefix are accepted, and the
//! spelling is part of the byte-exact record.

/// One parsed directive (the raw line rides alongside every variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `cargo:rerun-if-changed=PATH` — joins the observed closure.
    RerunIfChanged {
        /// The path, exactly as emitted.
        path: String,
    },
    /// `cargo:rerun-if-env-changed=VAR` — joins the env closure.
    RerunIfEnvChanged {
        /// The variable name.
        var: String,
    },
    /// `cargo:rustc-<kind>=VALUE` — reshapes downstream compiles.
    Rustc {
        /// The rustc directive kind (`cfg`, `link-lib`, `link-search`,
        /// `link-arg`, `env`, `flags`, …).
        kind: String,
        /// The value, exactly as emitted.
        value: String,
    },
    /// `cargo:warning=TEXT` — presentation, not semantics.
    Warning {
        /// The warning text.
        text: String,
    },
    /// `cargo:KEY=VALUE` metadata passed to dependent build scripts —
    /// semantic (dependents read it).
    Metadata {
        /// The key.
        key: String,
        /// The value.
        value: String,
    },
}

/// One captured stdout line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedLine {
    /// The ORIGINAL line bytes (byte-exact round-trip anchor).
    pub raw: String,
    /// The parse, when the line was a directive.
    pub directive: Option<Directive>,
}

/// The captured directive evidence for one build-script run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildScriptCapture {
    /// Every stdout line in order.
    pub lines: Vec<CapturedLine>,
}

impl BuildScriptCapture {
    /// Byte-exact reconstruction of the original stdout.
    #[must_use]
    pub fn reconstruct(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(&line.raw);
            out.push('\n');
        }
        out
    }

    /// The rerun-if-changed paths (join the observed input closure).
    pub fn rerun_paths(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::RerunIfChanged { path }) => Some(path.as_str()),
            _ => None,
        })
    }

    /// The rerun-if-env-changed variables (join the env closure).
    pub fn rerun_env_vars(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::RerunIfEnvChanged { var }) => Some(var.as_str()),
            _ => None,
        })
    }

    /// The semantic directives (everything except warnings) — the
    /// key-feeding subset.
    pub fn semantic_directives(&self) -> impl Iterator<Item = &Directive> {
        self.lines.iter().filter_map(|l| match &l.directive {
            Some(Directive::Warning { .. }) | None => None,
            Some(d) => Some(d),
        })
    }
}

/// Parse one line's directive, if any (`cargo:` and `cargo::` forms).
fn parse_line(line: &str) -> Option<Directive> {
    let rest = line
        .strip_prefix("cargo::")
        .or_else(|| line.strip_prefix("cargo:"))?;
    let (key, value) = rest.split_once('=')?;
    Some(match key {
        "rerun-if-changed" => Directive::RerunIfChanged {
            path: value.to_owned(),
        },
        "rerun-if-env-changed" => Directive::RerunIfEnvChanged {
            var: value.to_owned(),
        },
        "warning" => Directive::Warning {
            text: value.to_owned(),
        },
        _ => {
            if let Some(kind) = key.strip_prefix("rustc-") {
                Directive::Rustc {
                    kind: kind.to_owned(),
                    value: value.to_owned(),
                }
            } else {
                Directive::Metadata {
                    key: key.to_owned(),
                    value: value.to_owned(),
                }
            }
        }
    })
}

/// Capture a build script's stdout.
#[must_use]
pub fn capture_stdout(stdout: &str) -> BuildScriptCapture {
    BuildScriptCapture {
        lines: stdout
            .lines()
            .map(|line| CapturedLine {
                raw: line.to_owned(),
                directive: parse_line(line),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDOUT: &str = "\
cargo:rerun-if-changed=build/wrapper.h
cargo:rerun-if-env-changed=OPENSSL_DIR
cargo:rustc-cfg=has_avx2
cargo:rustc-link-lib=static=z
cargo:rustc-link-search=native=/__rabs/build/zlib-1/out
cargo:rustc-env=BUILD_PROFILE=release
cargo::rustc-check-cfg=cfg(has_avx2)
cargo:root=/__rabs/build/openssl-1/out
cargo:warning=using vendored openssl
plain non-directive output line
";

    #[test]
    fn directive_fixtures_round_trip_byte_exact() {
        // THE acceptance: reconstruct() equals the original bytes.
        let capture = capture_stdout(STDOUT);
        assert_eq!(capture.reconstruct(), STDOUT);
    }

    #[test]
    fn rerun_if_inputs_join_the_observed_closure() {
        let capture = capture_stdout(STDOUT);
        assert_eq!(
            capture.rerun_paths().collect::<Vec<_>>(),
            ["build/wrapper.h"]
        );
        assert_eq!(
            capture.rerun_env_vars().collect::<Vec<_>>(),
            ["OPENSSL_DIR"]
        );
    }

    #[test]
    fn rustc_metadata_and_warning_directives_classify() {
        let capture = capture_stdout(STDOUT);
        let semantic: Vec<&Directive> = capture.semantic_directives().collect();
        // rerun x2 + rustc x5 + metadata root=1 — warning excluded.
        assert_eq!(semantic.len(), 8);
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Rustc { kind, value }
                if kind == "link-lib" && value == "static=z"
        )));
        // Both prefixes parse; the raw spelling is retained.
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Rustc { kind, .. } if kind == "check-cfg"
        )));
        // Unknown key -> Metadata (dependents read it: semantic).
        assert!(semantic.iter().any(|d| matches!(
            d,
            Directive::Metadata { key, .. } if key == "root"
        )));
        // Warning parsed but NOT semantic.
        let all_warnings: Vec<_> = capture
            .lines
            .iter()
            .filter(|l| matches!(l.directive, Some(Directive::Warning { .. })))
            .collect();
        assert_eq!(all_warnings.len(), 1);
    }

    #[test]
    fn non_directive_output_is_preserved_not_dropped() {
        let capture = capture_stdout(STDOUT);
        let plain: Vec<_> = capture
            .lines
            .iter()
            .filter(|l| l.directive.is_none())
            .collect();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].raw, "plain non-directive output line");
    }
}
