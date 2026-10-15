//! Opt-in reuse across Cargo's final and intermediate build-directory layouts.
//!
//! Cargo interprets CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR and
//! CARGO_BUILD_BUILD_DIR before invoking rustc. Its actual output/search paths
//! remain in the invocation, but these inherited environment values otherwise
//! defeat cross-worktree reuse even when the compiler inputs are identical.
//!
//! RABS_REUSE_CARGO_TARGET_DIR retains its single-variable contract.
//! RABS_REUSE_CARGO_LAYOUT opts into all three placement variables. Only an
//! unambiguous, present execution/keyed binding is eligible. The compiler sees
//! the original environment; env!/option_env! reads of projected variables veto
//! publication through the existing dep-info closure guard. The policy binds
//! the exact projected presence set, never equating absent with present-empty.
//!
//! Each captured rustc-env directive remains exact independently: failure to
//! project one variable must not disable valid reuse of the others. Every trial
//! reruns the original validators and narrower profiles from a fresh original
//! plan, so composing projections cannot lose their policy identities or vetoes.

use rabs_key::action_key::compute_action_key;
use rabs_key::canonical::CanonicalEncoder;
use rabs_key::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use rabs_key::live_dependency::{
    DOMAIN_LIVE_ISOLATION, DependencyActionPlan, LiveDependencyKey, LiveRefusal,
};
use rabs_key::typed_digest::compute;
use std::sync::LazyLock;

const VARIABLE: &str = "CARGO_TARGET_DIR";
// Order is part of the versioned projection contract, not environment order.
const LAYOUT_VARIABLES: [&str; 3] = [VARIABLE, "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"];
const POLICY_TAG: &str = "rabs.live-dependency.cargo-target-placement.v1";
const LAYOUT_POLICY_TAG: &str = "rabs.live-dependency.cargo-layout-placement.v1";
static ENABLED: LazyLock<bool> = LazyLock::new(|| opt_in("RABS_REUSE_CARGO_TARGET_DIR"));
static LAYOUT_ENABLED: LazyLock<bool> = LazyLock::new(|| opt_in("RABS_REUSE_CARGO_LAYOUT"));

fn opt_in(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "on"))
}

pub(super) fn enabled() -> bool {
    *ENABLED
}

pub(super) fn layout_enabled() -> bool {
    *LAYOUT_ENABLED
}

fn single_value<'a>(env: &'a [(String, String)], variable: &str) -> Option<&'a str> {
    let mut entries = env.iter().filter(|(name, _)| name == variable);
    let (_, value) = entries.next()?;
    entries.next().is_none().then_some(value.as_str())
}

/// `derive` runs the ordinary validators and any narrower placement profile.
/// No candidate escapes until its complete descriptor and read veto agree.
pub(super) fn key(
    plan: &mut DependencyActionPlan,
    enable_target: bool,
    enable_layout: bool,
    derive: impl Fn(&mut DependencyActionPlan) -> Result<LiveDependencyKey, LiveRefusal>,
) -> Result<LiveDependencyKey, LiveRefusal> {
    let eligible: Vec<&str> = LAYOUT_VARIABLES
        .into_iter()
        .filter(|variable| enable_layout || (enable_target && *variable == VARIABLE))
        .filter(|variable| {
            let present = single_value(&plan.execution_env, variable);
            present.is_some() && present == single_value(&plan.keyed_env, variable)
        })
        .collect();
    if eligible.is_empty() {
        return derive(plan);
    }

    // Invalid original evidence must fail before optimization; derive may
    // install a narrower profile's veto, but cannot mutate the caller on error.
    let mut accepted_plan = plan.clone();
    let mut keyed = derive(&mut accepted_plan)?;
    let mut projected_names = Vec::new();
    for variable in eligible {
        // Never derive from accepted_plan: a narrower profile may have removed
        // OUT_DIR from keyed_env while retaining its real generated root. It
        // needs its ORIGINAL inputs to reconstruct its own policy on each trial.
        let mut trial = plan.clone();
        trial
            .keyed_env
            .retain(|(name, _)| name != variable && !projected_names.contains(&name.as_str()));
        let Ok(candidate) = derive(&mut trial) else {
            // A build-script directive can require this value to remain exact.
            // Keep earlier successful projections; later variables may still work.
            continue;
        };
        // Projection is permitted to change only keyed-env read vetoes. Refuse
        // a derivation that restores a removed binding or rewrites execution.
        let mut execution_contract = trial.clone();
        execution_contract.keyed_env = plan.keyed_env.clone();
        if execution_contract != *plan
            || trial
                .keyed_env
                .iter()
                .any(|(name, _)| name == variable || projected_names.contains(&name.as_str()))
        {
            continue;
        }
        projected_names.push(variable);
        accepted_plan = trial;
        keyed = candidate;
    }
    if !projected_names.is_empty() {
        bind_policy(&mut keyed, &projected_names);
    }
    *plan = accepted_plan;
    Ok(keyed)
}

fn bind_policy(keyed: &mut LiveDependencyKey, projected_names: &[&str]) {
    let original_policy = &keyed.descriptor.sandbox_semantic_policy;
    let mut policy = CanonicalEncoder::new();
    if projected_names == [VARIABLE] {
        // This is the identical established contract, independent of which
        // opt-in selected it. Keep its exact identity, not an unnecessary epoch.
        policy
            .str(POLICY_TAG)
            .str(original_policy.domain)
            .bytes(&original_policy.bytes)
            .str("CARGO_TARGET_DIR present; tracked reads refuse publication");
    } else {
        policy
            .str(LAYOUT_POLICY_TAG)
            .str(original_policy.domain)
            .bytes(&original_policy.bytes)
            .str("projected variables present; tracked reads refuse publication");
        for variable in projected_names {
            policy.str(variable);
        }
    }
    keyed.descriptor.sandbox_semantic_policy = compute(DOMAIN_LIVE_ISOLATION, &policy.finish());
    keyed.action_key = compute_action_key(&keyed.descriptor).final_key;
    keyed.descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&keyed.descriptor));
}

#[cfg(test)]
#[path = "cargo_placement_reuse_tests.rs"]
mod tests;
