//! Opt-in reuse across Cargo target-directory environment values.
//!
//! CARGO_TARGET_DIR is Cargo placement, but the live environment policy also
//! keys it as a possible env!/option_env! input. Distinct agent target roots
//! therefore miss even when all compiler arguments and captured inputs match.
//!
//! With RABS_REUSE_CARGO_TARGET_DIR=1, project only this variable's keyed value.
//! NEVER remove or rewrite its real execution value. The existing dep-info
//! closure guard refuses publication on a tracked read of this unkeyed, present
//! variable. The new policy identity distinguishes present from absent: a
//! compile observing absence must never seed a hit for a present value.
//!
//! Build-script rustc-env directives still require exact keying. A failed
//! projection falls back to the validated baseline, retaining any other
//! profile's tracked-read veto. No source scanning, output rewriting, or
//! serving/sampling/quarantine bypass is involved.

use rabs_key::action_key::compute_action_key;
use rabs_key::canonical::CanonicalEncoder;
use rabs_key::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use rabs_key::live_dependency::{
    DOMAIN_LIVE_ISOLATION, DependencyActionPlan, LiveDependencyKey, LiveRefusal,
};
use rabs_key::typed_digest::compute;
use std::sync::LazyLock;

const VARIABLE: &str = "CARGO_TARGET_DIR";
const POLICY_TAG: &str = "rabs.live-dependency.cargo-target-placement.v1";
static ENABLED: LazyLock<bool> = LazyLock::new(|| {
    matches!(
        std::env::var("RABS_REUSE_CARGO_TARGET_DIR").as_deref(),
        Ok("1" | "true" | "on")
    )
});

pub(super) fn enabled() -> bool {
    *ENABLED
}

fn single_value(env: &[(String, String)]) -> Option<&str> {
    let mut entries = env.iter().filter(|(name, _)| name == VARIABLE);
    let (_, value) = entries.next()?;
    entries.next().is_none().then_some(value.as_str())
}

/// `derive` runs the ordinary validators and any narrower placement profile.
/// Its candidate is private until the complete descriptor and read veto agree.
pub(super) fn key(
    plan: &mut DependencyActionPlan,
    enable_projection: bool,
    derive: impl Fn(&mut DependencyActionPlan) -> Result<LiveDependencyKey, LiveRefusal>,
) -> Result<LiveDependencyKey, LiveRefusal> {
    let present = single_value(&plan.execution_env);
    if !enable_projection || present.is_none() || present != single_value(&plan.keyed_env) {
        return derive(plan);
    }

    // Validate the original invocation first. Never let a projection rescue
    // invalid evidence; do not leak a partial plan mutation on failure.
    let mut baseline_plan = plan.clone();
    let baseline = derive(&mut baseline_plan)?;
    let mut projected = plan.clone();
    projected.keyed_env.retain(|(name, _)| name != VARIABLE);
    let Ok(mut keyed) = derive(&mut projected) else {
        // In particular, a captured rustc-env=CARGO_TARGET_DIR directive must
        // remain fully keyed, even when no later compiler read was observed.
        *plan = baseline_plan;
        return Ok(baseline);
    };

    let original_policy = &keyed.descriptor.sandbox_semantic_policy;
    let mut policy = CanonicalEncoder::new();
    policy
        .str(POLICY_TAG)
        .str(original_policy.domain)
        .bytes(&original_policy.bytes)
        .str("CARGO_TARGET_DIR present; tracked reads refuse publication");
    keyed.descriptor.sandbox_semantic_policy = compute(DOMAIN_LIVE_ISOLATION, &policy.finish());
    keyed.action_key = compute_action_key(&keyed.descriptor).final_key;
    keyed.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&keyed.descriptor));

    // The generated-root spelling, execution env, invocation and all guards
    // remain real. Only keyed-env vetoes produced by these profiles can differ.
    *plan = projected;
    Ok(keyed)
}

#[cfg(test)]
#[path = "cargo_placement_reuse_tests.rs"]
mod tests;
