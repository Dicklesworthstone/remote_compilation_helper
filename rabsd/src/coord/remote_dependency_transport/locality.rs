//! Bounded hints about dependency bytes a pinned worker may still retain.
//!
//! A successful compiler result identifies its output objects, not the state
//! of the worker's optional source cache. These hints may only break placement
//! ties: source-ready negotiation and private digest-verified import still
//! establish every input. No path, file handle, lease, or result authority is
//! retained here. A new worker process cannot inherit an old process's hints.

use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
use rabs_protocol::result_identity::{CanonicalActionResultManifest, OutputRole, TypedDigest};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const MAX_OBJECTS: usize = 4096;
// Bound the estimate as well as its storage. This is one ordinary maximum
// source projection, not a claim about any worker's configured cache budget.
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Process identity survives standby reconnects, unlike readiness generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerProcess {
    pub(crate) boot: WorkerBootGeneration,
    pub(crate) incarnation: WorkerIncarnationId,
}

impl WorkerProcess {
    pub(crate) fn from_hello(hello: &Value) -> Option<Self> {
        let boot = hello["boot_generation"].as_u64()?;
        let incarnation = hello["incarnation"].as_str()?;
        if boot == 0
            || incarnation.len() != 32
            || !incarnation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let incarnation = u128::from_str_radix(incarnation, 16).ok()?;
        (incarnation != 0).then_some(Self {
            boot: WorkerBootGeneration(boot),
            incarnation: WorkerIncarnationId(incarnation),
        })
    }
}

/// Deduplicated object identities from the request's already keyed inventory.
/// Paths and aliases do not multiply a worker's estimated reusable bytes.
#[derive(Debug, Default)]
pub(crate) struct SourceDemand(HashSet<TypedDigest>);

impl SourceDemand {
    pub(crate) fn new<'a>(objects: impl IntoIterator<Item = &'a TypedDigest>) -> Self {
        Self(objects.into_iter().take(MAX_OBJECTS).cloned().collect())
    }
}

/// Exact object identity from capture, paired with verified delivery length.
#[derive(Debug, Clone)]
pub(crate) struct ProducedObject {
    pub(crate) object: TypedDigest,
    pub(crate) bytes: u64,
}

/// Project only library outputs eligible for the worker's optional retention.
/// The caller has verified the delivery and captured its bytes into this
/// manifest. Wire SHA-256 and typed CAS identities are deliberately NOT compared:
/// the former hashes raw bytes, while the latter includes its domain framing.
pub(crate) fn captured_outputs(
    manifest: &CanonicalActionResultManifest,
    artifacts: &Value,
) -> Vec<ProducedObject> {
    let Some(files) = artifacts["files"].as_array() else {
        return Vec::new();
    };
    if files.len() > MAX_OBJECTS {
        return Vec::new();
    }
    let mut lengths = HashMap::new();
    for file in files {
        let Some(name) = file["name"].as_str() else {
            return Vec::new();
        };
        let Some(bytes) = file["bytes"].as_u64() else {
            return Vec::new();
        };
        let Some(executable) = file["executable"].as_bool() else {
            return Vec::new();
        };
        if lengths.insert(name, (bytes, executable)).is_some() {
            return Vec::new();
        }
    }
    manifest
        .logical_outputs
        .iter()
        .take(MAX_OBJECTS)
        .filter_map(|output| {
            if !matches!(
                output.role,
                OutputRole::Materializable | OutputRole::ProvisionalMetadata
            ) {
                return None;
            }
            let name = output.virtual_path.as_utf8()?;
            let basename = name.rsplit('/').next()?;
            if !basename.starts_with("lib")
                || !(basename.ends_with(".rmeta") || basename.ends_with(".rlib"))
            {
                return None;
            }
            let &(bytes, executable) = lengths.get(name)?;
            if executable || bytes == 0 || bytes > MAX_BYTES {
                return None;
            }
            Some(ProducedObject {
                object: output.object.0.clone(),
                bytes,
            })
        })
        .collect()
}

#[derive(Debug)]
struct Observation {
    bytes: u64,
    observed: Instant,
}

impl Observation {
    fn fresh(&self, now: Instant) -> bool {
        now.checked_duration_since(self.observed)
            .is_some_and(|age| age < MAX_AGE)
    }
}

/// Process-local estimates belonging to one explicitly pinned worker endpoint.
#[derive(Debug, Default)]
pub(crate) struct SourceLocality {
    process: Option<WorkerProcess>,
    objects: HashMap<TypedDigest, Observation>,
    bytes: u64,
}

impl SourceLocality {
    pub(crate) fn remember(
        &mut self,
        process: WorkerProcess,
        objects: &[ProducedObject],
        now: Instant,
    ) {
        if objects.is_empty() || process.boot.0 == 0 || process.incarnation.0 == 0 {
            return;
        }
        if self.process != Some(process) {
            self.objects.clear();
            self.process = Some(process);
        }
        self.objects.retain(|_, observation| observation.fresh(now));
        self.bytes = self.objects.values().map(|entry| entry.bytes).sum();
        for object in objects.iter().take(MAX_OBJECTS) {
            if object.bytes == 0 || object.bytes > MAX_BYTES {
                continue;
            }
            if let Some(previous) = self.objects.remove(&object.object) {
                self.bytes -= previous.bytes;
            }
            while self.objects.len() >= MAX_OBJECTS || object.bytes > MAX_BYTES - self.bytes {
                let Some(oldest) = self
                    .objects
                    .iter()
                    .min_by_key(|(_, observation)| observation.observed)
                    .map(|(object, _)| object.clone())
                else {
                    break;
                };
                if let Some(previous) = self.objects.remove(&oldest) {
                    self.bytes -= previous.bytes;
                }
            }
            self.objects.insert(
                object.object.clone(),
                Observation {
                    bytes: object.bytes,
                    observed: now,
                },
            );
            self.bytes += object.bytes;
        }
    }

    pub(crate) fn reusable_bytes(
        &self,
        process: WorkerProcess,
        demand: &SourceDemand,
        now: Instant,
    ) -> u64 {
        if self.process != Some(process) {
            return 0;
        }
        demand
            .0
            .iter()
            .filter_map(|object| self.objects.get(object))
            .filter(|observation| observation.fresh(now))
            .fold(0_u64, |bytes, observation| {
                bytes.saturating_add(observation.bytes)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{DigestAlgorithm, LogicalOutput, ObjectId, ResultKind};
    use serde_json::json;

    fn object(index: u64) -> TypedDigest {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&index.to_le_bytes());
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.sha256.v1",
            bytes,
        }
    }

    fn produced(index: u64, bytes: u64) -> ProducedObject {
        ProducedObject {
            object: object(index),
            bytes,
        }
    }

    fn process(boot: u64, incarnation: u128) -> WorkerProcess {
        WorkerProcess {
            boot: WorkerBootGeneration(boot),
            incarnation: WorkerIncarnationId(incarnation),
        }
    }

    #[test]
    fn wanted_objects_are_deduplicated_typed_and_bounded() {
        let now = Instant::now();
        let producer = process(1, 2);
        let mut locality = SourceLocality::default();
        locality.remember(producer, &[produced(1, 900), produced(2, 100)], now);
        let one = object(1);
        let mut foreign = one.clone();
        foreign.domain = "rabs.action-key.sha256.v1";
        let demand = SourceDemand::new([&one, &one, &foreign]);
        assert_eq!(locality.reusable_bytes(producer, &demand, now), 900);
        assert_eq!(
            locality.reusable_bytes(producer, &SourceDemand::new([&foreign]), now),
            0
        );
        let objects = (0..=MAX_OBJECTS as u64).map(object).collect::<Vec<_>>();
        let demand = SourceDemand::new(&objects);
        assert_eq!(demand.0.len(), MAX_OBJECTS);
        assert!(!demand.0.contains(&object(MAX_OBJECTS as u64)));
    }

    #[test]
    fn hints_expire_without_refreshing_on_lookup_and_reject_clock_regression() {
        let now = Instant::now();
        let producer = process(1, 2);
        let output = produced(1, 73);
        let demand = SourceDemand::new([&output.object]);
        let mut locality = SourceLocality::default();
        locality.remember(producer, &[output], now);
        assert_eq!(
            locality.reusable_bytes(producer, &demand, now + MAX_AGE - Duration::from_nanos(1)),
            73
        );
        assert_eq!(locality.reusable_bytes(producer, &demand, now + MAX_AGE), 0);
        assert_eq!(
            locality.reusable_bytes(producer, &demand, now - Duration::from_nanos(1)),
            0
        );
        locality.remember(producer, &[produced(2, 1)], now + MAX_AGE);
        assert_eq!(locality.objects.len(), 1);
        assert_eq!(locality.bytes, 1);
    }

    #[test]
    fn boots_and_incarnations_cannot_inherit_prior_output_hints() {
        let now = Instant::now();
        let old = process(7, 9);
        let new = process(8, 10);
        let demand = SourceDemand::new([&object(1), &object(2)]);
        let mut locality = SourceLocality::default();
        locality.remember(old, &[produced(1, 37)], now);
        assert_eq!(locality.reusable_bytes(old, &demand, now), 37);
        for other in [process(7, 10), process(8, 9), new] {
            assert_eq!(locality.reusable_bytes(other, &demand, now), 0);
        }
        locality.remember(new, &[produced(2, 91)], now);
        assert_eq!(locality.reusable_bytes(new, &demand, now), 91);
        assert_eq!(locality.reusable_bytes(old, &demand, now), 0);
        assert_eq!(locality.objects.len(), 1);
    }

    #[test]
    fn old_observations_yield_to_new_objects_within_file_and_byte_limits() {
        let now = Instant::now();
        let producer = process(1, 2);
        let mut locality = SourceLocality::default();
        locality.remember(producer, &[produced(1, MAX_BYTES - 1)], now);
        locality.remember(producer, &[produced(2, 2)], now + Duration::from_nanos(1));
        assert!(!locality.objects.contains_key(&object(1)));
        assert_eq!(locality.bytes, 2);
        locality.remember(
            producer,
            &[produced(2, 7), produced(3, 0), produced(4, u64::MAX)],
            now,
        );
        assert_eq!(locality.bytes, 7);
        assert_eq!(locality.objects.len(), 1);

        let mut locality = SourceLocality::default();
        for index in 0..=MAX_OBJECTS as u64 {
            locality.remember(
                producer,
                &[produced(index, 1)],
                now + Duration::from_nanos(index),
            );
        }
        assert_eq!(locality.objects.len(), MAX_OBJECTS);
        assert_eq!(locality.bytes, MAX_OBJECTS as u64);
        assert!(!locality.objects.contains_key(&object(0)));
        assert!(locality.objects.contains_key(&object(MAX_OBJECTS as u64)));
    }

    #[test]
    fn malformed_process_identity_cannot_establish_locality() {
        for hello in [
            json!({}),
            json!({"boot_generation":0,"incarnation":"00000000000000000000000000000001"}),
            json!({"boot_generation":1,"incarnation":"00000000000000000000000000000000"}),
            json!({"boot_generation":1,"incarnation":"1"}),
            json!({"boot_generation":1,"incarnation":"0000000000000000000000000000000G"}),
            json!({"boot_generation":"1","incarnation":"00000000000000000000000000000001"}),
        ] {
            assert_eq!(WorkerProcess::from_hello(&hello), None, "{hello}");
        }
        assert_eq!(
            WorkerProcess::from_hello(&json!({
                "boot_generation":9,"incarnation":"0123456789abcdef0123456789abcdef"
            })),
            Some(process(9, 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef))
        );
    }

    fn manifest(outputs: &[(&str, u64, OutputRole)]) -> CanonicalActionResultManifest {
        CanonicalActionResultManifest {
            action_key: object(91),
            canonical_descriptor_digest: object(92),
            key_epoch: 1,
            projection_epoch: 1,
            result_kind: ResultKind::Success,
            artifact_bundle_root: None,
            logical_outputs: outputs
                .iter()
                .map(|(name, index, role)| LogicalOutput {
                    role: *role,
                    virtual_path: RawBytes::new(name.as_bytes().to_vec()),
                    object: ObjectId(object(*index)),
                })
                .collect(),
            semantic_result_digest: object(93),
            observable_result_digest: object(94),
        }
    }

    #[test]
    fn capture_matches_exact_output_paths_lengths_and_roles_without_using_raw_sha() {
        let manifest = manifest(&[
            ("libunit.rlib", 1, OutputRole::Materializable),
            ("nested/libunit.rmeta", 2, OutputRole::ProvisionalMetadata),
            ("libexecutable.rlib", 3, OutputRole::Materializable),
            ("unit.d", 4, OutputRole::DepInfo),
            ("unrelated.rmeta", 5, OutputRole::Materializable),
            ("libmissing.rlib", 6, OutputRole::Materializable),
            ("libempty.rmeta", 7, OutputRole::ProvisionalMetadata),
            ("libtoo-large.rlib", 8, OutputRole::Materializable),
        ]);
        let mut files = json!({"files":[
            {"name":"libunit.rlib","bytes":900,"executable":false,"sha256":"different raw-byte identity"},
            {"name":"libunit.rmeta","bytes":800,"executable":false},
            {"name":"nested/libunit.rmeta","bytes":37,"executable":false},
            {"name":"libexecutable.rlib","bytes":1000,"executable":true},
            {"name":"unit.d","bytes":90,"executable":false},
            {"name":"unrelated.rmeta","bytes":1000,"executable":false},
            {"name":"libempty.rmeta","bytes":0,"executable":false},
            {"name":"libtoo-large.rlib","bytes":MAX_BYTES+1,"executable":false}
        ]});
        let outputs = captured_outputs(&manifest, &files);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].object, object(1));
        assert_eq!(outputs[0].bytes, 900);
        assert_eq!(outputs[1].object, object(2));
        assert_eq!(outputs[1].bytes, 37);
        files["files"].as_array_mut().unwrap().push(json!({
            "name":"libunit.rlib","bytes":900,"executable":false
        }));
        assert!(captured_outputs(&manifest, &files).is_empty());
        assert!(captured_outputs(&manifest, &Value::Null).is_empty());
    }
}
