//! Compiler-event/pipelining contract classification (bead F025;
//! invariant I24's conservative edge; plan §68; risk R55).
//!
//! F021 split presentation from semantics; this module owns the ONE
//! classification table deciding which side a compiler-event or
//! pipelining setting lives on. The conservative rule:
//!
//! - a setting is `Presentation` ONLY with a versioned,
//!   toolchain-specific proof that it cannot change semantic output or
//!   exit behavior (the proof's identity is part of the table row —
//!   toolchain change invalidates it);
//! - anything ambiguous stays `Semantic` — it keys the action. Wrongly
//!   classifying a semantic flag as presentation serves WRONG results;
//!   wrongly keeping a presentation flag semantic only costs hit rate.
//!   The asymmetry decides every doubt;
//! - unknown settings are `Semantic` by default (the table is an
//!   allowlist of proven-presentation rows, never a blocklist).

/// Where a setting lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractClass {
    /// Keys the action (default; every doubt lands here).
    Semantic,
    /// Proven presentation-only under the named proof.
    Presentation {
        /// Versioned, toolchain-specific proof identity.
        proof: &'static str,
    },
}

/// One classification-table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractRow {
    /// The setting (flag name or event-contract knob).
    pub setting: &'static str,
    /// Its class.
    pub class: ContractClass,
}

/// The classification table (append rows only with their proofs).
pub const CONTRACT_TABLE: &[ContractRow] = &[
    // Proven presentation: rendering-only surfaces. Proof IDs name the
    // toolchain-specific verification corpus entry that demonstrated
    // byte-identical artifacts and exit codes across the setting.
    ContractRow {
        setting: "--color",
        class: ContractClass::Presentation {
            proof: "rabs-proof.color-render-only.rustc-stable.v1",
        },
    },
    ContractRow {
        setting: "--diagnostic-width",
        class: ContractClass::Presentation {
            proof: "rabs-proof.width-render-only.rustc-stable.v1",
        },
    },
    ContractRow {
        setting: "--error-format",
        class: ContractClass::Presentation {
            proof: "rabs-proof.error-format-render-only.rustc-stable.v1",
        },
    },
    ContractRow {
        setting: "--json",
        class: ContractClass::Presentation {
            proof: "rabs-proof.json-artifact-notifications.rustc-stable.v1",
        },
    },
    // Semantic: these change artifacts or exit behavior.
    ContractRow {
        setting: "-D",
        class: ContractClass::Semantic, // deny changes exit codes
    },
    ContractRow {
        setting: "--cap-lints",
        class: ContractClass::Semantic, // caps change emitted lints/exit
    },
    ContractRow {
        setting: "--emit",
        class: ContractClass::Semantic, // changes artifacts outright
    },
    // Pipelining contract: WHEN the rmeta event fires is scheduling,
    // but WHETHER metadata is produced is semantic; the knob stays
    // semantic because the two are not separable at the flag level.
    ContractRow {
        setting: "-Z:emit-metadata-timing",
        class: ContractClass::Semantic,
    },
];

/// Classify a setting: table hit or the Semantic default.
#[must_use]
pub fn classify(setting: &str) -> ContractClass {
    CONTRACT_TABLE
        .iter()
        .find(|row| row.setting == setting)
        .map_or(ContractClass::Semantic, |row| row.class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_and_unknown_settings_stay_semantic() {
        // THE acceptance fixture: an ambiguous diagnostic flag not in
        // the proven table keys the action.
        assert_eq!(classify("--future-diag-flag"), ContractClass::Semantic);
        assert_eq!(classify("-Zmystery-event-knob"), ContractClass::Semantic);
        // Lint level/caps: semantic (exit behavior).
        assert_eq!(classify("-D"), ContractClass::Semantic);
        assert_eq!(classify("--cap-lints"), ContractClass::Semantic);
    }

    #[test]
    fn presentation_rows_all_carry_versioned_toolchain_proofs() {
        // Structural enforcement of the bead rule: NO presentation row
        // without a named, versioned, toolchain-specific proof.
        for row in CONTRACT_TABLE {
            if let ContractClass::Presentation { proof } = row.class {
                assert!(
                    proof.starts_with("rabs-proof."),
                    "{}: proof must be a registered proof ID",
                    row.setting
                );
                assert!(
                    proof.contains(".rustc-"),
                    "{}: proof must name its toolchain",
                    row.setting
                );
                assert!(
                    proof.ends_with(".v1"),
                    "{}: proof must be versioned",
                    row.setting
                );
            }
        }
    }

    #[test]
    fn table_is_consistent_with_the_f003_exclusion_allowlist() {
        // The F003 parser drops exactly --color/--diagnostic-width; both
        // must be proven-presentation here (the parser's allowlist is a
        // VIEW of this table, not an independent decision).
        assert!(matches!(
            classify("--color"),
            ContractClass::Presentation { .. }
        ));
        assert!(matches!(
            classify("--diagnostic-width"),
            ContractClass::Presentation { .. }
        ));
        // --json/--error-format are proven presentation-classified here
        // but F003 conservatively passes them through to the key today
        // (sound: over-keying costs hits, never correctness). Their
        // parser exclusion is gated on adopting this table there.
        assert!(matches!(
            classify("--json"),
            ContractClass::Presentation { .. }
        ));
    }

    #[test]
    fn table_has_no_duplicate_settings() {
        let mut names: Vec<&str> = CONTRACT_TABLE.iter().map(|r| r.setting).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }
}
