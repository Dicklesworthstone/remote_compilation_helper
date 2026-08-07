//! Link result bundle + diagnostics replay (bead L004; plan §101).
//!
//! A link action's cacheable result is MORE than the linked artifact:
//! stock `cargo`/`rustc` shows the user the linker's warnings and
//! exits with the linker's status. A cache hit that drops either is
//! observably different from the link it replaces. So:
//!
//! - link outputs AND diagnostics are cached ATOMICALLY as one
//!   `LinkResultBundle` — there is no API that persists the outputs
//!   without the diagnostics (the bundle is the only unit);
//! - only a SUCCESSFUL link bundles: a nonzero exit is a refusal,
//!   never a cached failure served later as truth;
//! - replay reproduces the diagnostics BYTE-IDENTICALLY (stdout and
//!   stderr separately, in their original streams) and the exit
//!   semantics;
//! - the output set is validated at bundling: at least one output,
//!   no duplicate logical names.
//!
//! The acceptance is link-hit equivalence: replaying the bundle of a
//! stock link is observationally equal to the stock link itself.

use rabs_protocol::result_identity::TypedDigest;

/// One linked output (logical name → content identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOutput {
    /// Logical output name (the F035 logical map's key, e.g.
    /// `bin/rch`).
    pub logical_name: String,
    /// Content identity of the linked artifact.
    pub digest: TypedDigest,
}

/// What the stock link observably did (the bundling input AND the
/// equivalence oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockLinkOutcome {
    /// Outputs the linker produced.
    pub outputs: Vec<LinkOutput>,
    /// Linker stdout bytes.
    pub stdout: Vec<u8>,
    /// Linker stderr bytes (warnings live here).
    pub stderr: Vec<u8>,
    /// Linker exit code.
    pub exit_code: i32,
}

/// Typed bundling refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRefusal {
    /// The link failed: a failure is re-run, never cached as truth.
    LinkFailed {
        /// The observed exit code.
        exit_code: i32,
    },
    /// The link produced no outputs (not a link result at all).
    NoOutputs,
    /// Two outputs claimed one logical name.
    DuplicateLogicalName(String),
}

/// The atomic cacheable unit: outputs + diagnostics together.
///
/// Constructed ONLY through [`LinkResultBundle::bundle`] — the fields
/// are private, so no path exists that stores outputs without their
/// diagnostics or skips validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkResultBundle {
    outputs: Vec<LinkOutput>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// A replayed link hit: what the client observes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedLink {
    /// Outputs to materialize.
    pub outputs: Vec<LinkOutput>,
    /// Stdout bytes to emit, byte-identical.
    pub stdout: Vec<u8>,
    /// Stderr bytes to emit, byte-identical (warnings preserved).
    pub stderr: Vec<u8>,
    /// Exit code (always the successful link's 0).
    pub exit_code: i32,
}

impl LinkResultBundle {
    /// Bundle a stock link outcome atomically.
    ///
    /// # Errors
    /// [`BundleRefusal`] on failed links, empty output sets, or
    /// duplicate logical names.
    pub fn bundle(outcome: &StockLinkOutcome) -> Result<Self, BundleRefusal> {
        if outcome.exit_code != 0 {
            return Err(BundleRefusal::LinkFailed {
                exit_code: outcome.exit_code,
            });
        }
        if outcome.outputs.is_empty() {
            return Err(BundleRefusal::NoOutputs);
        }
        for (i, output) in outcome.outputs.iter().enumerate() {
            if outcome.outputs[..i]
                .iter()
                .any(|prior| prior.logical_name == output.logical_name)
            {
                return Err(BundleRefusal::DuplicateLogicalName(
                    output.logical_name.clone(),
                ));
            }
        }
        Ok(Self {
            outputs: outcome.outputs.clone(),
            stdout: outcome.stdout.clone(),
            stderr: outcome.stderr.clone(),
        })
    }

    /// Replay the bundle as a link hit: diagnostics and exit
    /// semantics preserved.
    #[must_use]
    pub fn replay(&self) -> ReplayedLink {
        ReplayedLink {
            outputs: self.outputs.clone(),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            exit_code: 0, // only successful links bundle
        }
    }
}

/// Link-hit equivalence: is a replayed hit observationally equal to
/// a stock link outcome?
#[must_use]
pub fn equivalent_to_stock(replayed: &ReplayedLink, stock: &StockLinkOutcome) -> bool {
    replayed.outputs == stock.outputs
        && replayed.stdout == stock.stdout
        && replayed.stderr == stock.stderr
        && replayed.exit_code == stock.exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        }
    }

    fn stock_link() -> StockLinkOutcome {
        StockLinkOutcome {
            outputs: vec![
                LinkOutput {
                    logical_name: "bin/rch".into(),
                    digest: d(1),
                },
                LinkOutput {
                    logical_name: "bin/rch.dwp".into(),
                    digest: d(2),
                },
            ],
            stdout: b"".to_vec(),
            stderr: b"warning: linking against system libunwind\n".to_vec(),
            exit_code: 0,
        }
    }

    #[test]
    fn link_hit_equivalence_vs_stock_link() {
        // THE acceptance: bundle the stock link, replay it, and the
        // replay is observationally EQUAL — outputs, both diagnostic
        // streams byte-identical, exit semantics.
        let stock = stock_link();
        let bundle = LinkResultBundle::bundle(&stock).expect("clean link bundles");
        let replayed = bundle.replay();
        assert!(equivalent_to_stock(&replayed, &stock));
        assert_eq!(replayed.stderr, stock.stderr, "warnings byte-identical");
        assert_eq!(replayed.stdout, stock.stdout);
        assert_eq!(replayed.exit_code, 0);
        assert_eq!(replayed.outputs.len(), 2);
        // Planted negative: perturb any observable and equivalence
        // FAILS — the oracle is not vacuous.
        let mut wrong = replayed.clone();
        wrong.stderr = b"".to_vec(); // a hit that dropped the warning
        assert!(!equivalent_to_stock(&wrong, &stock));
        let mut wrong = bundle.replay();
        wrong.outputs.pop();
        assert!(!equivalent_to_stock(&wrong, &stock));
    }

    #[test]
    fn a_failed_link_never_bundles() {
        // A failure is re-run, never cached and served as truth.
        let mut failed = stock_link();
        failed.exit_code = 1;
        failed.stderr = b"error: undefined symbol: _main\n".to_vec();
        assert_eq!(
            LinkResultBundle::bundle(&failed),
            Err(BundleRefusal::LinkFailed { exit_code: 1 })
        );
    }

    #[test]
    fn output_set_validation_at_bundling() {
        let mut empty = stock_link();
        empty.outputs.clear();
        assert_eq!(
            LinkResultBundle::bundle(&empty),
            Err(BundleRefusal::NoOutputs)
        );
        let mut dup = stock_link();
        dup.outputs.push(LinkOutput {
            logical_name: "bin/rch".into(), // already claimed
            digest: d(9),
        });
        assert_eq!(
            LinkResultBundle::bundle(&dup),
            Err(BundleRefusal::DuplicateLogicalName("bin/rch".into()))
        );
    }

    #[test]
    fn the_bundle_is_atomic_by_construction() {
        // Structural: fields are private and the only constructor is
        // bundle() — no path stores outputs without diagnostics. The
        // replay returns every component in one unit.
        let bundle = LinkResultBundle::bundle(&stock_link()).expect("bundles");
        let ReplayedLink {
            outputs,
            stdout,
            stderr,
            exit_code,
        } = bundle.replay(); // exhaustive: a new observable is a
        // compile error here until replay carries it
        assert!(!outputs.is_empty());
        assert!(stdout.is_empty() && !stderr.is_empty());
        assert_eq!(exit_code, 0);
    }
}
