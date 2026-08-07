//! Edge/coordinator/worker region-tree constructors (bead G001; Epic G
//! trees; invariant I7's ownership shape).
//!
//! The plan's ownership trees, built as data by constructors so the
//! SHAPE is testable and the tracing/crashpack attribution chain is
//! derivable for every node: a leaked effect anywhere attributes to
//! region → coordinator authority → build operation → action
//! generation → action → attempt, because every node's path carries
//! the attribution values of its ancestors.
//!
//! These specs drive the live `Cx` region wiring (the runtime spawn
//! adapters consume them as the authoritative nesting); the tree data
//! itself stays pure so the lab and unit tests can assert structure
//! without a runtime.

/// Attribution facts a region node may carry (accumulated down the
/// tree; renders into every trace/crashpack line).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attribution {
    /// Coordinator authority (term/incarnation rendering).
    pub coordinator_authority: Option<String>,
    /// Build operation ID rendering.
    pub build_operation: Option<String>,
    /// Action key rendering.
    pub action_key: Option<String>,
    /// Action generation rendering.
    pub action_generation: Option<String>,
    /// Attempt ID rendering.
    pub attempt: Option<String>,
    /// Execution lease rendering.
    pub lease: Option<String>,
    /// Worker boot generation rendering.
    pub worker_boot_generation: Option<String>,
}

/// One region-tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionSpec {
    /// Region name (the plan's own vocabulary).
    pub name: &'static str,
    /// Attribution values INTRODUCED at this node (children inherit).
    pub introduces: Attribution,
    /// Nested regions.
    pub children: Vec<RegionSpec>,
}

impl RegionSpec {
    fn leaf(name: &'static str) -> Self {
        Self {
            name,
            introduces: Attribution::default(),
            children: vec![],
        }
    }

    fn node(name: &'static str, children: Vec<RegionSpec>) -> Self {
        Self {
            name,
            introduces: Attribution::default(),
            children,
        }
    }
}

/// The edge root tree (plan Epic G, edge side).
#[must_use]
pub fn edge_root(command: &str) -> RegionSpec {
    let mut cargo_driver = RegionSpec::node(
        "CargoDriverRegion",
        vec![
            RegionSpec::leaf("CargoRootPermitRegion"),
            RegionSpec::leaf("CoherentSnapshotRegion"),
            RegionSpec::leaf("PathTranslationRegion"),
            RegionSpec::leaf("SubscriberRegion"),
            RegionSpec::leaf("LocalMaterializationOrFallbackRegion"),
        ],
    );
    cargo_driver.introduces.build_operation = Some(command.to_owned());
    RegionSpec::node(
        "RabsEdgeRoot",
        vec![
            RegionSpec::node(
                "LocalApiRegion",
                vec![RegionSpec::leaf("WrapperConnectionRegion")],
            ),
            RegionSpec::leaf("CoordinatorSessionRegion"),
            cargo_driver,
            RegionSpec::leaf("EdgeObjectCacheRegion"),
            RegionSpec::leaf("EdgeObservabilityRegion"),
        ],
    )
}

/// The coordinator root tree, bound to its authority.
#[must_use]
pub fn coordinator_root(authority: &str, action_key: &str, generation: &str) -> RegionSpec {
    let mut action_region = RegionSpec::node(
        "ActionRegion",
        vec![
            RegionSpec::leaf("SubscriberSet"),
            RegionSpec::leaf("CacheLookup"),
            RegionSpec::node("AttemptSet", vec![RegionSpec::leaf("AttemptProxy")]),
            RegionSpec::leaf("OutputVerification"),
            RegionSpec::leaf("Publication"),
        ],
    );
    action_region.introduces.action_key = Some(action_key.to_owned());
    action_region.introduces.action_generation = Some(generation.to_owned());
    let mut root = RegionSpec::node(
        "RabsCoordinatorRoot",
        vec![
            RegionSpec::leaf("EdgeSessionRegion"),
            RegionSpec::node(
                "WorkerFleetRegion",
                vec![
                    RegionSpec::leaf("WorkerSessionRegion"),
                    RegionSpec::leaf("HealthCollector"),
                ],
            ),
            RegionSpec::leaf("BuildOperationRegistryRegion"),
            RegionSpec::leaf("DiscoveryRegistryRegion"),
            RegionSpec::node("ActionRegistryRegion", vec![action_region]),
            RegionSpec::leaf("SchedulerAndRootPermitRegion"),
            RegionSpec::leaf("SpeculationRegion"),
            RegionSpec::leaf("GarbageCollectionRegion"),
            RegionSpec::leaf("ReconciliationRegion"),
            RegionSpec::leaf("ObservabilityRegion"),
        ],
    );
    root.introduces.coordinator_authority = Some(authority.to_owned());
    root
}

/// The worker attempt tree, bound to its full fencing tuple.
#[must_use]
pub fn worker_attempt_region(
    action_key: &str,
    generation: &str,
    attempt: &str,
    lease: &str,
    boot_generation: &str,
) -> RegionSpec {
    let mut root = RegionSpec::node(
        "WorkerActionAttemptRegion",
        vec![
            RegionSpec::leaf("ObjectFetch"),
            RegionSpec::leaf("SandboxMaterialization"),
            RegionSpec::leaf("InputEnforcementAndTrace"),
            RegionSpec::node(
                "CompilerProcessRegion",
                vec![
                    RegionSpec::leaf("StdoutDrain"),
                    RegionSpec::leaf("StderrDrain"),
                    RegionSpec::leaf("DescendantProcessGroup"),
                ],
            ),
            RegionSpec::leaf("EarlyMetadata"),
            RegionSpec::leaf("OutputHarvest"),
            RegionSpec::leaf("OutputUpload"),
            RegionSpec::leaf("PreparedResultOffer"),
            RegionSpec::leaf("CleanupFinalizer"),
        ],
    );
    root.introduces = Attribution {
        action_key: Some(action_key.to_owned()),
        action_generation: Some(generation.to_owned()),
        attempt: Some(attempt.to_owned()),
        lease: Some(lease.to_owned()),
        worker_boot_generation: Some(boot_generation.to_owned()),
        ..Attribution::default()
    };
    root
}

/// Render the attribution chain for every node: `(path, attribution)`
/// pairs where attribution accumulates ancestor introductions — the
/// exact lines tracing/crashpacks stamp on leaked effects.
#[must_use]
pub fn attribution_chains(root: &RegionSpec) -> Vec<(String, Attribution)> {
    fn merge(base: &Attribution, over: &Attribution) -> Attribution {
        Attribution {
            coordinator_authority: over
                .coordinator_authority
                .clone()
                .or_else(|| base.coordinator_authority.clone()),
            build_operation: over
                .build_operation
                .clone()
                .or_else(|| base.build_operation.clone()),
            action_key: over.action_key.clone().or_else(|| base.action_key.clone()),
            action_generation: over
                .action_generation
                .clone()
                .or_else(|| base.action_generation.clone()),
            attempt: over.attempt.clone().or_else(|| base.attempt.clone()),
            lease: over.lease.clone().or_else(|| base.lease.clone()),
            worker_boot_generation: over
                .worker_boot_generation
                .clone()
                .or_else(|| base.worker_boot_generation.clone()),
        }
    }
    fn walk(
        node: &RegionSpec,
        path: &str,
        inherited: &Attribution,
        out: &mut Vec<(String, Attribution)>,
    ) {
        let path = if path.is_empty() {
            node.name.to_owned()
        } else {
            format!("{path}/{}", node.name)
        };
        let attribution = merge(inherited, &node.introduces);
        out.push((path.clone(), attribution.clone()));
        for child in &node.children {
            walk(child, &path, &attribution, out);
        }
    }
    let mut out = Vec::new();
    walk(root, "", &Attribution::default(), &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_build_the_documented_trees() {
        let edge = edge_root("cargo build");
        let names: Vec<&str> = edge.children.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
                "LocalApiRegion",
                "CoordinatorSessionRegion",
                "CargoDriverRegion",
                "EdgeObjectCacheRegion",
                "EdgeObservabilityRegion",
            ]
        );
        let coordinator = coordinator_root("term-3", "key-abc", "generation-42");
        assert_eq!(coordinator.children.len(), 10);
        let worker =
            worker_attempt_region("key-abc", "generation-42", "attempt-7", "lease-1", "boot-3");
        assert_eq!(worker.children.len(), 9);
        // The compiler process region contains its three drains.
        let compiler = worker
            .children
            .iter()
            .find(|c| c.name == "CompilerProcessRegion")
            .unwrap();
        assert_eq!(compiler.children.len(), 3);
    }

    #[test]
    fn every_worker_leaf_carries_the_full_attribution_chain() {
        // THE acceptance: a leaked effect in ANY worker sub-region
        // attributes to key, generation, attempt, lease, and boot
        // generation — the deepest leaves included.
        let worker =
            worker_attempt_region("key-abc", "generation-42", "attempt-7", "lease-1", "boot-3");
        for (path, attribution) in attribution_chains(&worker) {
            assert_eq!(attribution.action_key.as_deref(), Some("key-abc"), "{path}");
            assert_eq!(
                attribution.action_generation.as_deref(),
                Some("generation-42"),
                "{path}"
            );
            assert_eq!(attribution.attempt.as_deref(), Some("attempt-7"), "{path}");
            assert_eq!(attribution.lease.as_deref(), Some("lease-1"), "{path}");
            assert_eq!(
                attribution.worker_boot_generation.as_deref(),
                Some("boot-3"),
                "{path}"
            );
        }
    }

    #[test]
    fn coordinator_action_subtree_inherits_authority_and_action_identity() {
        let coordinator = coordinator_root("term-3", "key-abc", "generation-42");
        let chains = attribution_chains(&coordinator);
        // The Publication leaf under ActionRegion: full chain.
        let (path, attribution) = chains
            .iter()
            .find(|(p, _)| p.ends_with("ActionRegion/Publication"))
            .unwrap();
        assert!(path.starts_with("RabsCoordinatorRoot/ActionRegistryRegion"));
        assert_eq!(attribution.coordinator_authority.as_deref(), Some("term-3"));
        assert_eq!(attribution.action_key.as_deref(), Some("key-abc"));
        assert_eq!(
            attribution.action_generation.as_deref(),
            Some("generation-42")
        );
        // Regions OUTSIDE the action subtree carry authority but not
        // action identity.
        let (_, gc) = chains
            .iter()
            .find(|(p, _)| p.ends_with("GarbageCollectionRegion"))
            .unwrap();
        assert_eq!(gc.coordinator_authority.as_deref(), Some("term-3"));
        assert_eq!(gc.action_key, None);
    }

    #[test]
    fn edge_cargo_driver_introduces_the_build_operation() {
        let edge = edge_root("cargo build -p app");
        let chains = attribution_chains(&edge);
        let (_, subscriber) = chains
            .iter()
            .find(|(p, _)| p.ends_with("SubscriberRegion"))
            .unwrap();
        assert_eq!(
            subscriber.build_operation.as_deref(),
            Some("cargo build -p app")
        );
        // Regions outside the driver carry no operation.
        let (_, cache) = chains
            .iter()
            .find(|(p, _)| p.ends_with("EdgeObjectCacheRegion"))
            .unwrap();
        assert_eq!(cache.build_operation, None);
    }
}
