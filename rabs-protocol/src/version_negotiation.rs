//! ATP/RABS version negotiation (bead J002; Asupersync blocker 44.2;
//! risk R64).
//!
//! Every session opens with an explicit version handshake. Rules:
//!
//! - both sides advertise a CONCRETE transport range and application
//!   range (`current` + `minimum_compatible`) — there is no "ATP/0+"
//!   wildcard: any later version gets a concrete negotiated number
//!   checked against the matrix;
//! - negotiation picks the highest version inside BOTH ranges;
//! - mismatch produces a TYPED refusal carrying both sides' ranges so
//!   the operator sees exactly what to upgrade;
//! - N/N-1 is the supported skew: fixtures pin that a current node
//!   negotiates with a one-behind node, and that older skews refuse.

/// A concrete version range: minimum compatible to current, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    /// Minimum version this side still speaks.
    pub minimum_compatible: u32,
    /// Current (preferred) version.
    pub current: u32,
}

impl VersionRange {
    /// Whether this range is well-formed.
    #[must_use]
    pub const fn well_formed(&self) -> bool {
        self.minimum_compatible <= self.current
    }
}

/// One side's hello: transport + application ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionHello {
    /// ATP transport version range.
    pub transport: VersionRange,
    /// RABS application version range.
    pub application: VersionRange,
}

/// Negotiation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// Agreed: the concrete versions BOTH sides run for this session.
    Agreed {
        /// Negotiated transport version.
        transport: u32,
        /// Negotiated application version.
        application: u32,
    },
    /// Refused: the typed unsupported-version response.
    Refused(VersionRefusal),
}

/// The typed refusal — both sides' ranges travel so the operator sees
/// exactly what to upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRefusal {
    /// Which layer failed to overlap.
    pub layer: RefusedLayer,
    /// Our range for that layer.
    pub ours: VersionRange,
    /// Their range for that layer.
    pub theirs: VersionRange,
}

/// Which layer refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RefusedLayer {
    Transport,
    Application,
    MalformedHello,
}

/// Highest version inside both ranges, if any.
const fn overlap(a: VersionRange, b: VersionRange) -> Option<u32> {
    let low = if a.minimum_compatible > b.minimum_compatible {
        a.minimum_compatible
    } else {
        b.minimum_compatible
    };
    let high = if a.current < b.current {
        a.current
    } else {
        b.current
    };
    if low <= high { Some(high) } else { None }
}

/// Negotiate a session from both hellos.
#[must_use]
pub fn negotiate(ours: &VersionHello, theirs: &VersionHello) -> Negotiation {
    if !ours.transport.well_formed()
        || !ours.application.well_formed()
        || !theirs.transport.well_formed()
        || !theirs.application.well_formed()
    {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::MalformedHello,
            ours: ours.transport,
            theirs: theirs.transport,
        });
    }
    let Some(transport) = overlap(ours.transport, theirs.transport) else {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::Transport,
            ours: ours.transport,
            theirs: theirs.transport,
        });
    };
    let Some(application) = overlap(ours.application, theirs.application) else {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::Application,
            ours: ours.application,
            theirs: theirs.application,
        });
    };
    Negotiation::Agreed {
        transport,
        application,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The N node: transport 3 (min 2), application 7 (min 6).
    fn current_node() -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 2,
                current: 3,
            },
            application: VersionRange {
                minimum_compatible: 6,
                current: 7,
            },
        }
    }

    /// The N-1 node.
    fn n_minus_1() -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 2,
            },
            application: VersionRange {
                minimum_compatible: 5,
                current: 6,
            },
        }
    }

    #[test]
    fn n_n_minus_1_negotiates_the_older_concrete_versions() {
        // THE rolling-upgrade fixture: N with N-1 agrees on concrete
        // numbers (the highest both speak) — no wildcard, no ambiguity.
        assert_eq!(
            negotiate(&current_node(), &n_minus_1()),
            Negotiation::Agreed {
                transport: 2,
                application: 6
            }
        );
        // Symmetric: both sides derive the same answer.
        assert_eq!(
            negotiate(&n_minus_1(), &current_node()),
            Negotiation::Agreed {
                transport: 2,
                application: 6
            }
        );
        // N with N: the current versions.
        assert_eq!(
            negotiate(&current_node(), &current_node()),
            Negotiation::Agreed {
                transport: 3,
                application: 7
            }
        );
    }

    #[test]
    fn stale_skew_refuses_with_both_ranges() {
        // An N-2 node (transport current 1 < our minimum 2): typed
        // transport refusal carrying BOTH ranges.
        let n_minus_2 = VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 1,
            },
            application: VersionRange {
                minimum_compatible: 5,
                current: 5,
            },
        };
        let Negotiation::Refused(refusal) = negotiate(&current_node(), &n_minus_2) else {
            panic!("N-2 must refuse");
        };
        assert_eq!(refusal.layer, RefusedLayer::Transport);
        assert_eq!(refusal.ours.minimum_compatible, 2);
        assert_eq!(refusal.theirs.current, 1);
    }

    #[test]
    fn application_layer_refuses_independently_of_transport() {
        // Transports overlap; applications do not: the refusal names
        // the APPLICATION layer.
        let app_stale = VersionHello {
            transport: current_node().transport,
            application: VersionRange {
                minimum_compatible: 3,
                current: 4, // < our minimum 6
            },
        };
        let Negotiation::Refused(refusal) = negotiate(&current_node(), &app_stale) else {
            panic!("stale application must refuse");
        };
        assert_eq!(refusal.layer, RefusedLayer::Application);
    }

    #[test]
    fn future_versions_get_concrete_numbers_never_wildcards() {
        // An N+3 peer: we still negotiate OUR current — a concrete
        // number inside both ranges — never "whatever you have".
        let future = VersionHello {
            transport: VersionRange {
                minimum_compatible: 2,
                current: 6,
            },
            application: VersionRange {
                minimum_compatible: 6,
                current: 10,
            },
        };
        assert_eq!(
            negotiate(&current_node(), &future),
            Negotiation::Agreed {
                transport: 3,
                application: 7
            }
        );
        // Malformed hello (min > current): typed refusal, not UB.
        let malformed = VersionHello {
            transport: VersionRange {
                minimum_compatible: 9,
                current: 3,
            },
            application: current_node().application,
        };
        assert!(matches!(
            negotiate(&current_node(), &malformed),
            Negotiation::Refused(VersionRefusal {
                layer: RefusedLayer::MalformedHello,
                ..
            })
        ));
    }

    #[test]
    fn a010_asupersync_upgrade_report_generated_for_synthetic_pin_bump_and_ci_blocks_unattached_changes()
     {
        let baseline = AsupersyncPinSnapshot {
            git_rev: "107adf1df8d274b37c6ed9a12471fe3da44429f2".into(),
            crate_version: "0.4.11".into(),
            public_symbols: vec![
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::RuntimeBuilder::current_thread".into(),
                    signature_hash: 0x1001,
                    consumed_by_adapter: true,
                    adapter_module: Some("rabs_asupersync::daemon_runtime".into()),
                },
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::Cx::spawn".into(),
                    signature_hash: 0x2001,
                    consumed_by_adapter: true,
                    adapter_module: Some("rabs_asupersync::region_tree".into()),
                },
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::wasm::BrowserReactor::new".into(),
                    signature_hash: 0x9001,
                    consumed_by_adapter: false,
                    adapter_module: None,
                },
            ],
            features: vec![
                AsupersyncFeatureNode {
                    feature_name: "proc-macros".into(),
                    enabled_dependencies: vec!["asupersync-macros".into()],
                    in_rabs_runtime_profile: true,
                    forbidden_in_runtime: false,
                },
                AsupersyncFeatureNode {
                    feature_name: "tls".into(),
                    enabled_dependencies: vec!["rustls".into()],
                    in_rabs_runtime_profile: true,
                    forbidden_in_runtime: false,
                },
            ],
            requires_durable_schema_epoch_bump: false,
        };

        // Synthetic pin bump to 0.5.0: Cx::spawn signature/behavior updated (intersecting
        // rabs_asupersync::region_tree), unconsumed wasm symbol changed (filtered out of
        // adapter surface delta), and proc-macros/tls profile preserved.
        let candidate = AsupersyncPinSnapshot {
            git_rev: "78b64636e99fea4ea2d868096576021dd3b8e519".into(),
            crate_version: "0.5.0".into(),
            public_symbols: vec![
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::RuntimeBuilder::current_thread".into(),
                    signature_hash: 0x1001,
                    consumed_by_adapter: true,
                    adapter_module: Some("rabs_asupersync::daemon_runtime".into()),
                },
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::Cx::spawn".into(),
                    signature_hash: 0x2002, // changed!
                    consumed_by_adapter: true,
                    adapter_module: Some("rabs_asupersync::region_tree".into()),
                },
                AsupersyncPublicSymbol {
                    symbol_path: "asupersync::wasm::BrowserReactor::new".into(),
                    signature_hash: 0x9999, // changed, but NOT in rabs-asupersync adapter surface
                    consumed_by_adapter: false,
                    adapter_module: None,
                },
            ],
            features: baseline.features.clone(),
            requires_durable_schema_epoch_bump: false,
        };

        let report = generate_asupersync_upgrade_report(&baseline, &candidate);
        assert_eq!(report.from_rev, baseline.git_rev);
        assert_eq!(report.to_rev, candidate.git_rev);
        assert_eq!(
            report.intersecting_api_deltas.len(),
            1,
            "only changes intersecting rabs-asupersync adapter surface enter the bounded review set"
        );
        assert_eq!(
            report.intersecting_api_deltas[0].symbol_path,
            "asupersync::Cx::spawn"
        );
        assert_eq!(
            report.intersecting_api_deltas[0].change_kind,
            AsupersyncDeltaKind::Modified
        );
        assert_eq!(report.unconsumed_api_changes_ignored, 1);
        assert!(report.feature_deltas.is_empty());
        let markdown = report.render_markdown();
        assert!(markdown.contains("asupersync::Cx::spawn"));
        assert!(markdown.contains("rabs_asupersync::region_tree"));

        // CI Gate 1: Pin bump without an attached report is BLOCKED.
        assert_eq!(
            verify_asupersync_pin_change_ci_gate(
                &candidate.git_rev,
                &candidate.git_rev,
                None,
                true,
                false,
            ),
            Err(AsupersyncPinGateRefusal::MissingAttachedUpgradeReport)
        );

        // CI Gate 2: Attached report for a different revision is BLOCKED.
        assert_eq!(
            verify_asupersync_pin_change_ci_gate(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                Some(&report),
                true,
                false,
            ),
            Err(AsupersyncPinGateRefusal::ReportRevisionMismatch)
        );

        // CI Gate 3: Intersecting adapter surface changed without green A009 contract suite is BLOCKED.
        assert_eq!(
            verify_asupersync_pin_change_ci_gate(
                &candidate.git_rev,
                &candidate.git_rev,
                Some(&report),
                false,
                false,
            ),
            Err(AsupersyncPinGateRefusal::ContractSuiteNotVerified)
        );

        // CI Gate 4: Attached report + matching ADR rev + green A009 contract suite PASSES.
        assert_eq!(
            verify_asupersync_pin_change_ci_gate(
                &candidate.git_rev,
                &candidate.git_rev,
                Some(&report),
                true,
                false,
            ),
            Ok(())
        );
    }
}

/// One public symbol exported by an Asupersync revision (bead A010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsupersyncPublicSymbol {
    /// Fully qualified symbol path (e.g. `asupersync::Cx::spawn`).
    pub symbol_path: String,
    /// Hash of the public signature/trait bounds.
    pub signature_hash: u64,
    /// Whether `rabs-asupersync` imports or adapts this symbol.
    pub consumed_by_adapter: bool,
    /// The `rabs-asupersync` module that adapts this symbol, if consumed.
    pub adapter_module: Option<String>,
}

/// One Cargo feature node in the Asupersync feature graph (bead A010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsupersyncFeatureNode {
    /// Feature name.
    pub feature_name: String,
    /// Transitive dependencies/features enabled by this feature.
    pub enabled_dependencies: Vec<String>,
    /// Whether enabled in the minimal `rabs-profile` (`["proc-macros", "tls"]`).
    pub in_rabs_runtime_profile: bool,
    /// Whether forbidden in the RABS runtime profile (`wasm-*`, `nightly-outcome-try`, etc.).
    pub forbidden_in_runtime: bool,
}

/// Snapshot of an Asupersync revision's public API and feature graph (bead A010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsupersyncPinSnapshot {
    /// Exact 40-char git revision SHA.
    pub git_rev: String,
    /// Crate version string.
    pub crate_version: String,
    /// Exported public symbols.
    pub public_symbols: Vec<AsupersyncPublicSymbol>,
    /// Cargo feature graph nodes.
    pub features: Vec<AsupersyncFeatureNode>,
    /// Whether any behavioral change alters durable RABS schema/key semantics.
    pub requires_durable_schema_epoch_bump: bool,
}

/// Kind of delta observed between two Asupersync snapshots (bead A010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsupersyncDeltaKind {
    /// Newly added symbol or feature.
    Added,
    /// Signature or feature dependency graph modified.
    Modified,
    /// Symbol or feature removed.
    Removed,
}

/// One public API change that intersects the `rabs-asupersync` adapter surface (bead A010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntersectingApiDelta {
    /// Changed symbol path.
    pub symbol_path: String,
    /// Consuming `rabs-asupersync` module.
    pub adapter_module: String,
    /// Delta classification.
    pub change_kind: AsupersyncDeltaKind,
}

/// One feature-graph change affecting the `rabs-profile` or forbidden feature set (bead A010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureGraphDelta {
    /// Changed feature name.
    pub feature_name: String,
    /// Delta classification.
    pub change_kind: AsupersyncDeltaKind,
    /// Whether a forbidden feature entered the runtime profile.
    pub introduces_forbidden_runtime_feature: bool,
}

/// Reviewable report generated by the A010 upgrade bot before any Asupersync pin update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsupersyncUpgradeReport {
    /// Previous pinned git revision.
    pub from_rev: String,
    /// Candidate pinned git revision.
    pub to_rev: String,
    /// Previous crate version.
    pub from_version: String,
    /// Candidate crate version.
    pub to_version: String,
    /// Public API changes that intersect `rabs-asupersync`.
    pub intersecting_api_deltas: Vec<IntersectingApiDelta>,
    /// Count of upstream API changes outside `rabs-asupersync`'s consumed surface (filtered out).
    pub unconsumed_api_changes_ignored: usize,
    /// Feature graph changes affecting the RABS runtime profile.
    pub feature_deltas: Vec<FeatureGraphDelta>,
    /// Whether the candidate requires a durable schema/key epoch bump (ADR 007 rule 4).
    pub requires_durable_schema_epoch_bump: bool,
}

impl AsupersyncUpgradeReport {
    /// Render a deterministic markdown review report suitable for ADR 007 attachment.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = format!(
            "### A010 Asupersync Upgrade Report (`{}` -> `{}`)\n\n\
             - Crate version: `{}` -> `{}`\n\
             - Intersecting `rabs-asupersync` API deltas: {}\n\
             - Unconsumed upstream API deltas ignored: {}\n\
             - Feature graph deltas: {}\n\
             - Durable schema/key epoch bump required: {}\n\n\
             | Consumed symbol | Adapter module | Change |\n\
             |---|---|---|\n",
            self.from_rev,
            self.to_rev,
            self.from_version,
            self.to_version,
            self.intersecting_api_deltas.len(),
            self.unconsumed_api_changes_ignored,
            self.feature_deltas.len(),
            self.requires_durable_schema_epoch_bump,
        );
        for d in &self.intersecting_api_deltas {
            out.push_str(&format!(
                "| `{}` | `{}` | `{:?}` |\n",
                d.symbol_path, d.adapter_module, d.change_kind
            ));
        }
        out
    }
}

/// Diff two Asupersync snapshots and produce a bounded `AsupersyncUpgradeReport` (bead A010).
#[must_use]
pub fn generate_asupersync_upgrade_report(
    baseline: &AsupersyncPinSnapshot,
    candidate: &AsupersyncPinSnapshot,
) -> AsupersyncUpgradeReport {
    let mut intersecting_api_deltas = Vec::new();
    let mut unconsumed_api_changes_ignored = 0usize;

    for old_sym in &baseline.public_symbols {
        match candidate
            .public_symbols
            .iter()
            .find(|s| s.symbol_path == old_sym.symbol_path)
        {
            Some(new_sym) => {
                if old_sym.signature_hash != new_sym.signature_hash {
                    if old_sym.consumed_by_adapter || new_sym.consumed_by_adapter {
                        intersecting_api_deltas.push(IntersectingApiDelta {
                            symbol_path: old_sym.symbol_path.clone(),
                            adapter_module: old_sym
                                .adapter_module
                                .clone()
                                .or_else(|| new_sym.adapter_module.clone())
                                .unwrap_or_else(|| "rabs_asupersync".into()),
                            change_kind: AsupersyncDeltaKind::Modified,
                        });
                    } else {
                        unconsumed_api_changes_ignored += 1;
                    }
                }
            }
            None => {
                if old_sym.consumed_by_adapter {
                    intersecting_api_deltas.push(IntersectingApiDelta {
                        symbol_path: old_sym.symbol_path.clone(),
                        adapter_module: old_sym
                            .adapter_module
                            .clone()
                            .unwrap_or_else(|| "rabs_asupersync".into()),
                        change_kind: AsupersyncDeltaKind::Removed,
                    });
                } else {
                    unconsumed_api_changes_ignored += 1;
                }
            }
        }
    }

    for new_sym in &candidate.public_symbols {
        if !baseline
            .public_symbols
            .iter()
            .any(|s| s.symbol_path == new_sym.symbol_path)
        {
            if new_sym.consumed_by_adapter {
                intersecting_api_deltas.push(IntersectingApiDelta {
                    symbol_path: new_sym.symbol_path.clone(),
                    adapter_module: new_sym
                        .adapter_module
                        .clone()
                        .unwrap_or_else(|| "rabs_asupersync".into()),
                    change_kind: AsupersyncDeltaKind::Added,
                });
            } else {
                unconsumed_api_changes_ignored += 1;
            }
        }
    }

    let mut feature_deltas = Vec::new();
    for old_feat in &baseline.features {
        match candidate
            .features
            .iter()
            .find(|f| f.feature_name == old_feat.feature_name)
        {
            Some(new_feat) => {
                if old_feat != new_feat {
                    feature_deltas.push(FeatureGraphDelta {
                        feature_name: old_feat.feature_name.clone(),
                        change_kind: AsupersyncDeltaKind::Modified,
                        introduces_forbidden_runtime_feature: new_feat.in_rabs_runtime_profile
                            && new_feat.forbidden_in_runtime,
                    });
                }
            }
            None => {
                if old_feat.in_rabs_runtime_profile {
                    feature_deltas.push(FeatureGraphDelta {
                        feature_name: old_feat.feature_name.clone(),
                        change_kind: AsupersyncDeltaKind::Removed,
                        introduces_forbidden_runtime_feature: false,
                    });
                }
            }
        }
    }
    for new_feat in &candidate.features {
        if !baseline
            .features
            .iter()
            .any(|f| f.feature_name == new_feat.feature_name)
            && (new_feat.in_rabs_runtime_profile || new_feat.forbidden_in_runtime)
        {
            feature_deltas.push(FeatureGraphDelta {
                feature_name: new_feat.feature_name.clone(),
                change_kind: AsupersyncDeltaKind::Added,
                introduces_forbidden_runtime_feature: new_feat.in_rabs_runtime_profile
                    && new_feat.forbidden_in_runtime,
            });
        }
    }

    AsupersyncUpgradeReport {
        from_rev: baseline.git_rev.clone(),
        to_rev: candidate.git_rev.clone(),
        from_version: baseline.crate_version.clone(),
        to_version: candidate.crate_version.clone(),
        intersecting_api_deltas,
        unconsumed_api_changes_ignored,
        feature_deltas,
        requires_durable_schema_epoch_bump: candidate.requires_durable_schema_epoch_bump,
    }
}

/// Refusal reasons when the CI gate blocks an Asupersync pin update (bead A010; ADR 007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsupersyncPinGateRefusal {
    /// Pin changed without an attached A010 upgrade report.
    MissingAttachedUpgradeReport,
    /// `Cargo.toml` revision, ADR 007 revision, and attached report revision do not match.
    ReportRevisionMismatch,
    /// Feature diff introduces a forbidden feature into the runtime profile.
    ForbiddenFeatureInRuntimeProfile,
    /// Intersecting adapter surface changed without a passing A009 contract suite run.
    ContractSuiteNotVerified,
    /// Behavioral change alters durable semantics without a schema/key epoch bump.
    DurableSchemaEpochNotBumped,
}

/// Enforce the CI pin-update gate (bead A010; ADR 007): blocks any Asupersync pin change
/// that lacks a matching upgrade report, violates the minimal feature profile, or lacks
/// contract-suite / epoch-bump verification.
///
/// # Errors
/// Returns [`AsupersyncPinGateRefusal`] when any ADR 007 / A010 upgrade requirement is unmet.
pub fn verify_asupersync_pin_change_ci_gate(
    manifest_rev: &str,
    adr_current_rev: &str,
    attached_report: Option<&AsupersyncUpgradeReport>,
    contract_suite_passed: bool,
    schema_epoch_bumped: bool,
) -> Result<(), AsupersyncPinGateRefusal> {
    let Some(report) = attached_report else {
        return Err(AsupersyncPinGateRefusal::MissingAttachedUpgradeReport);
    };
    if manifest_rev != adr_current_rev || report.to_rev != manifest_rev {
        return Err(AsupersyncPinGateRefusal::ReportRevisionMismatch);
    }
    if report
        .feature_deltas
        .iter()
        .any(|f| f.introduces_forbidden_runtime_feature)
    {
        return Err(AsupersyncPinGateRefusal::ForbiddenFeatureInRuntimeProfile);
    }
    if !report.intersecting_api_deltas.is_empty() && !contract_suite_passed {
        return Err(AsupersyncPinGateRefusal::ContractSuiteNotVerified);
    }
    if report.requires_durable_schema_epoch_bump && !schema_epoch_bumped {
        return Err(AsupersyncPinGateRefusal::DurableSchemaEpochNotBumped);
    }
    Ok(())
}
