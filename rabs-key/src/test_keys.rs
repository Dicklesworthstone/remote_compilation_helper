//! Per-test and batch action keys (bead O002; plan §102; risk R84's
//! test arm).
//!
//! Test caching keys on EVERYTHING that can change a test's outcome:
//!
//! - the test BINARY digest — which conservatively invalidates every
//!   test in that binary on any change (finer code-to-test
//!   projections are advisory research, not identity; there is no
//!   field through which one could narrow the invalidation);
//! - the exact test identity, the runner identity (O001), arguments,
//!   presented environment (F006), sandbox policy, positive+negative
//!   data inputs (E010), virtual cwd, output platform (F008), and
//!   declared side-effect outputs (F011);
//! - BATCH keys additionally include the shared state that motivated
//!   batching (the fixture database, the shared server socket) — two
//!   batches over the same cases with different shared state are
//!   different actions.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for per-test keys.
pub const DOMAIN_TEST_ACTION_KEY: &str = "rabs.test-action-key.v1";
/// Digest domain for batch keys.
pub const DOMAIN_TEST_BATCH_KEY: &str = "rabs.test-batch-key.v1";

/// The per-test key inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestActionInputs {
    /// The test binary's content digest (conservative invalidation).
    pub test_binary_digest: TypedDigest,
    /// The exact test identity (`module::tests::case`).
    pub test_identity: String,
    /// Runner identity (the O001 contract's tool).
    pub runner_identity: TypedDigest,
    /// Arguments to the case.
    pub arguments: Vec<String>,
    /// Presented-environment digest (F006).
    pub environment: TypedDigest,
    /// Sandbox semantic policy digest (E001).
    pub sandbox_policy: TypedDigest,
    /// Positive+negative data-input digests (E010 sets).
    pub data_inputs: TypedDigest,
    /// Virtual cwd digest.
    pub virtual_cwd: TypedDigest,
    /// Output-platform digest (F008).
    pub output_platform: TypedDigest,
    /// Declared side-effect outputs digest (F011).
    pub declared_side_effects: TypedDigest,
}

fn encode_digest(enc: &mut CanonicalEncoder, digest: &TypedDigest) {
    enc.str(digest.domain).bytes(&digest.bytes);
}

impl TestActionInputs {
    /// The per-test action key.
    #[must_use]
    pub fn test_key(&self) -> TypedDigest {
        let Self {
            test_binary_digest,
            test_identity,
            runner_identity,
            arguments,
            environment,
            sandbox_policy,
            data_inputs,
            virtual_cwd,
            output_platform,
            declared_side_effects,
        } = self;
        let mut enc = CanonicalEncoder::new();
        encode_digest(&mut enc, test_binary_digest);
        enc.str(test_identity);
        encode_digest(&mut enc, runner_identity);
        enc.u64(arguments.len() as u64);
        for argument in arguments {
            enc.str(argument);
        }
        encode_digest(&mut enc, environment);
        encode_digest(&mut enc, sandbox_policy);
        encode_digest(&mut enc, data_inputs);
        encode_digest(&mut enc, virtual_cwd);
        encode_digest(&mut enc, output_platform);
        encode_digest(&mut enc, declared_side_effects);
        compute(DOMAIN_TEST_ACTION_KEY, &enc.finish())
    }
}

/// A policy-selected batch: cases plus the SHARED STATE that motivated
/// batching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBatchInputs {
    /// The member cases' per-test keys, sorted at hashing.
    pub member_keys: Vec<TypedDigest>,
    /// The shared state's digest (fixture DB, shared server, ...).
    pub shared_state: TypedDigest,
}

impl TestBatchInputs {
    /// The batch key.
    #[must_use]
    pub fn batch_key(&self) -> TypedDigest {
        let mut members: Vec<&TypedDigest> = self.member_keys.iter().collect();
        members.sort_by(|a, b| (a.domain, &a.bytes).cmp(&(b.domain, &b.bytes)));
        let mut enc = CanonicalEncoder::new();
        enc.u64(members.len() as u64);
        for member in members {
            encode_digest(&mut enc, member);
        }
        encode_digest(&mut enc, &self.shared_state);
        compute(DOMAIN_TEST_BATCH_KEY, &enc.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn inputs(binary_tag: u8, case: &str) -> TestActionInputs {
        TestActionInputs {
            test_binary_digest: d("rabs.object.v1", binary_tag),
            test_identity: case.into(),
            runner_identity: d("rabs.tool-binary.v1", 2),
            arguments: vec!["--exact".into(), case.into()],
            environment: d("rabs.env.v1", 3),
            sandbox_policy: d("rabs.sandbox-policy.v1", 4),
            data_inputs: d("rabs.inputs.v1", 5),
            virtual_cwd: d("rabs.cwd.v1", 6),
            output_platform: d("rabs.output-platform.v1", 7),
            declared_side_effects: d("rabs.outputs.v1", 8),
        }
    }

    #[test]
    fn binary_change_invalidates_all_cases() {
        // THE acceptance: two cases in one binary; a binary change
        // forks BOTH keys — no projection can narrow it.
        let case_a_v1 = inputs(1, "parser::tests::round_trip").test_key();
        let case_b_v1 = inputs(1, "parser::tests::escaping").test_key();
        let case_a_v2 = inputs(9, "parser::tests::round_trip").test_key();
        let case_b_v2 = inputs(9, "parser::tests::escaping").test_key();
        assert_ne!(case_a_v1, case_a_v2, "case A invalidated");
        assert_ne!(case_b_v1, case_b_v2, "case B invalidated");
        // And distinct cases stay distinct within one binary.
        assert_ne!(case_a_v1, case_b_v1);
    }

    #[test]
    fn every_key_input_participates() {
        let base = inputs(1, "case").test_key();
        let mutations: Vec<TestActionInputs> = vec![
            {
                let mut m = inputs(1, "case");
                m.runner_identity = d("rabs.tool-binary.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.arguments.push("--nocapture".into());
                m
            },
            {
                let mut m = inputs(1, "case");
                m.environment = d("rabs.env.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.sandbox_policy = d("rabs.sandbox-policy.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.data_inputs = d("rabs.inputs.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.virtual_cwd = d("rabs.cwd.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.output_platform = d("rabs.output-platform.v1", 99);
                m
            },
            {
                let mut m = inputs(1, "case");
                m.declared_side_effects = d("rabs.outputs.v1", 99);
                m
            },
        ];
        for (i, mutated) in mutations.iter().enumerate() {
            assert_ne!(base, mutated.test_key(), "mutation {i} must fork");
        }
    }

    #[test]
    fn batch_keys_include_the_shared_state_and_are_order_insensitive() {
        let a = inputs(1, "case-a").test_key();
        let b = inputs(1, "case-b").test_key();
        let forward = TestBatchInputs {
            member_keys: vec![a.clone(), b.clone()],
            shared_state: d("rabs.object.v1", 50),
        };
        let reversed = TestBatchInputs {
            member_keys: vec![b, a],
            shared_state: d("rabs.object.v1", 50),
        };
        assert_eq!(
            forward.batch_key(),
            reversed.batch_key(),
            "member enumeration order is not semantics"
        );
        // The shared state that MOTIVATED batching keys: a different
        // fixture DB is a different batch action.
        let other_db = TestBatchInputs {
            shared_state: d("rabs.object.v1", 51),
            ..forward.clone()
        };
        assert_ne!(forward.batch_key(), other_db.batch_key());
    }
}
