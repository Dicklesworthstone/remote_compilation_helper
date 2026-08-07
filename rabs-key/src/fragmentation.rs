//! Key-fragmentation aggregation (bead F018; plan §70; feeds the Q011
//! fragmentation analyzer).
//!
//! When hit rates sag, the question is WHICH component fragments the
//! key space: dependency versions, feature sets, toolchains, flags,
//! path policies. The aggregator folds `ActionKeyBreakdown`s into
//! per-component histograms — how many distinct values each component
//! took, and how often each value occurred.
//!
//! **Privacy is structural**: the aggregator consumes only the
//! breakdown's component DIGESTS. Raw values (env bytes, paths, secret
//! digests' preimages) never reach this module — a histogram bucket is
//! `(digest, count)`, and the digest is already the only form the
//! breakdown carries. The leak-check test enumerates the output type's
//! reachable data to prove no byte-level value can appear.

use rabs_protocol::result_identity::TypedDigest;

use crate::action_key::ActionKeyBreakdown;

/// One value bucket: an opaque component digest and its occurrence count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueBucket {
    /// The component value's digest (opaque — never the value).
    pub digest: TypedDigest,
    /// How many observed keys carried this value.
    pub count: u64,
}

/// Histogram for one component across the observed fleet window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentHistogram {
    /// Component name (a schema constant, e.g. `"toolchain"`).
    pub component: &'static str,
    /// Distinct observed values with counts, descending by count.
    pub buckets: Vec<ValueBucket>,
}

impl ComponentHistogram {
    /// Number of distinct values (the fragmentation signal: a
    /// component with 40 distinct values across 45 keys is the
    /// fragmenter; one with 2 is not).
    #[must_use]
    pub fn distinct_values(&self) -> usize {
        self.buckets.len()
    }

    /// Total observations.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.count).sum()
    }
}

/// Fold a window of key breakdowns into per-component histograms.
/// Component order follows the breakdown's own component order;
/// buckets sort descending by count (ties by digest bytes for
/// determinism).
#[must_use]
pub fn aggregate(breakdowns: &[ActionKeyBreakdown]) -> Vec<ComponentHistogram> {
    let mut histograms: Vec<ComponentHistogram> = Vec::new();
    for breakdown in breakdowns {
        for component in &breakdown.components {
            let hist = match histograms
                .iter_mut()
                .find(|h| h.component == component.name)
            {
                Some(h) => h,
                None => {
                    histograms.push(ComponentHistogram {
                        component: component.name,
                        buckets: Vec::new(),
                    });
                    histograms.last_mut().expect("just pushed")
                }
            };
            match hist
                .buckets
                .iter_mut()
                .find(|b| b.digest == component.digest)
            {
                Some(bucket) => bucket.count += 1,
                None => hist.buckets.push(ValueBucket {
                    digest: component.digest.clone(),
                    count: 1,
                }),
            }
        }
    }
    for hist in &mut histograms {
        hist.buckets.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.digest.bytes.cmp(&b.digest.bytes))
        });
    }
    histograms
}

/// The top fragmenting components: sorted by distinct-value count
/// descending, keeping components with more than one observed value.
#[must_use]
pub fn top_fragmenters(histograms: &[ComponentHistogram]) -> Vec<(&'static str, usize)> {
    let mut out: Vec<(&'static str, usize)> = histograms
        .iter()
        .filter(|h| h.distinct_values() > 1)
        .map(|h| (h.component, h.distinct_values()))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_key::compute_action_key;
    use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn descriptor(toolchain_tag: u8, env_tag: u8) -> ActionDescriptor {
        ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::RustcDependencyCompile,
            normalized_invocation: d("rabs.invocation.v1", 1),
            virtual_working_directory: d("rabs.cwd.v1", 2),
            action_inputs: d("rabs.inputs.v1", 3),
            negative_dependencies: d("rabs.negdeps.v1", 4),
            dependency_inputs: d("rabs.deps.v1", 5),
            toolchain: d("rabs.toolchain-contract.v1", toolchain_tag),
            output_platform: d("rabs.output-platform.v1", 7),
            environment: d("rabs.env.v1", env_tag),
            sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
            build_path_semantic_policy: d("rabs.path-policy.v1", 10),
            execution_semantics: d("rabs.exec-semantics.v1", 11),
            output_declarations: d("rabs.outputs.v1", 12),
        }
    }

    #[test]
    fn histograms_attribute_fragmentation_to_the_right_component() {
        // Fleet window: 4 keys — one toolchain everywhere, but FOUR
        // distinct environments. The fragmenter must be `environment`.
        let breakdowns: Vec<_> = (0..4)
            .map(|i| compute_action_key(&descriptor(1, 100 + i)))
            .collect();
        let hists = aggregate(&breakdowns);
        let env = hists.iter().find(|h| h.component == "environment").unwrap();
        let tc = hists.iter().find(|h| h.component == "toolchain").unwrap();
        assert_eq!(env.distinct_values(), 4);
        assert_eq!(tc.distinct_values(), 1);
        assert_eq!(env.total(), 4);
        let top = top_fragmenters(&hists);
        assert_eq!(top.first(), Some(&("environment", 4)));
        // Non-fragmenting components (1 distinct value) are excluded.
        assert!(top.iter().all(|(name, _)| *name != "toolchain"));
    }

    #[test]
    fn bucket_counts_and_ordering_are_deterministic() {
        // 3 keys with env A, 1 with env B: buckets sorted by count.
        let mut window = vec![
            compute_action_key(&descriptor(1, 50)),
            compute_action_key(&descriptor(1, 50)),
            compute_action_key(&descriptor(1, 51)),
            compute_action_key(&descriptor(1, 50)),
        ];
        let hists = aggregate(&window);
        let env = hists.iter().find(|h| h.component == "environment").unwrap();
        assert_eq!(env.buckets[0].count, 3);
        assert_eq!(env.buckets[1].count, 1);
        // Input order does not change the aggregation.
        window.reverse();
        assert_eq!(aggregate(&window), hists);
    }

    #[test]
    fn output_carries_only_digests_never_values() {
        // Privacy proof at the type level: exhaustively destructure the
        // output — the ONLY data reachable is (component name constant,
        // digest domain constant, digest bytes, count). No field of any
        // raw value type (paths, env bytes, flags) exists to leak.
        let hists = aggregate(&[compute_action_key(&descriptor(1, 2))]);
        for ComponentHistogram { component, buckets } in hists {
            let _: &'static str = component; // schema constant
            for ValueBucket { digest, count } in buckets {
                let TypedDigest {
                    algorithm: _,
                    domain,
                    bytes,
                } = digest;
                let _: &'static str = domain; // domain constant
                let _: [u8; 32] = bytes; // opaque hash
                let _: u64 = count;
            }
        }
    }
}
