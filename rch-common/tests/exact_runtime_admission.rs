use rch_common::capability_probe::{
    CapabilityRequirement, CapabilityVerdict, assess_admissibility, parse_capability_probe,
};

fn facts() -> rch_common::ProbedFacts {
    parse_capability_probe(concat!(
        "RCH_FACT worker_version=rch-wkr 2.1.22\n",
        "RCH_FACT worker_protocol=1\n",
        "RCH_FACT node_version=v26.7.0\n",
        "RCH_FACT bun_version=1.3.0\n",
        "RCH_FACT tool=clang\n",
    ))
}

#[test]
fn exact_runtime_admission_requires_every_runtime_and_named_tool() {
    let mut facts = facts();
    let requirement =
        CapabilityRequirement::default().with_tools(["node@26.7.0", "bun@1.3.0", "clang"]);
    assert_eq!(
        assess_admissibility(&facts, &requirement),
        CapabilityVerdict::Admissible
    );
    facts.runtimes.node_version = Some("v22.0.0".to_owned());
    let CapabilityVerdict::Rejected { detail, .. } = assess_admissibility(&facts, &requirement)
    else {
        panic!("incompatible Node admitted");
    };
    assert_eq!(
        detail,
        "capability_missing:runtime_version:node:required=26.7.0:observed=22.0.0"
    );
    facts.runtimes.node_version = Some("v26.7.0".to_owned());
    facts.tools_present.clear();
    assert!(matches!(
        assess_admissibility(&facts, &requirement),
        CapabilityVerdict::Rejected { .. }
    ));
}

#[test]
fn exact_runtime_admission_never_substitutes_named_labels_for_version_facts() {
    let mut facts = facts();
    facts.runtimes.node_version = None;
    facts.tools_present.push("node@26.7.0".to_owned());
    let requirement = CapabilityRequirement::default().with_tools(["node@26.7.0"]);
    let CapabilityVerdict::Rejected { detail, .. } = assess_admissibility(&facts, &requirement)
    else {
        panic!("named label cannot prove runtime identity");
    };
    assert!(detail.ends_with("observed=<unknown>"));
    facts.tools_present.push("rust@1.90.0".to_owned());
    assert!(matches!(
        assess_admissibility(
            &facts,
            &CapabilityRequirement::default().with_tools(["rust@1.90.0"])
        ),
        CapabilityVerdict::Rejected { .. }
    ));
}

#[test]
fn unconstrained_and_named_only_requests_keep_existing_meaning() {
    let mut facts = facts();
    facts.runtimes.node_version = None;
    facts.runtimes.bun_version = None;
    assert_eq!(
        assess_admissibility(&facts, &CapabilityRequirement::default()),
        CapabilityVerdict::Admissible
    );
    assert_eq!(
        assess_admissibility(
            &facts,
            &CapabilityRequirement::default().with_tools(["clang"])
        ),
        CapabilityVerdict::Admissible
    );
    assert!(matches!(
        assess_admissibility(
            &facts,
            &CapabilityRequirement::default().with_tools(["node"])
        ),
        CapabilityVerdict::Rejected { .. }
    ));
}
