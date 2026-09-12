//! Action-key assembly and the `ActionKeyBreakdown` (bead F012; plan
//! §17/§10.3).
//!
//! Key construction returns the key AND a structured, redaction-safe
//! breakdown of contributing components — the breakdown is what `rch why
//! miss` diffs (F013), what offline audits inspect, and what makes every
//! miss attributable. The key is computed as:
//!
//! ```text
//! ActionKey = SHA-256_typed( DOMAIN_ACTION_KEY,
//!     canonical( key_epoch, projection_epoch, action_class_tag,
//!                the twelve component digests in declaration order ) )
//! ```
//!
//! using F001 canonical encoding, F034 typed framing, and A014's
//! exhaustive component list — so a descriptor field added without a key
//! decision is unrepresentable, and any serialization drift trips the
//! F001 goldens.

use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::{DOMAIN_ACTION_KEY, compute};

/// Positive input component domain, shared with descriptor schema vocabulary.
pub const DOMAIN_ACTION_INPUT_MANIFEST: &str = "rabs.inputs.v1";

/// A manifest cannot be assigned a canonical input-component identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputManifestError {
    /// The schema has no encoder in this version.
    UnsupportedSchema {
        /// The unsupported version supplied by the caller.
        found: u32,
    },
    /// More than one positive input names the same raw virtual path.
    DuplicatePositivePath,
    /// More than one enumeration names the same raw virtual directory.
    DuplicateEnumerationPath,
}

impl std::fmt::Display for InputManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { found } => {
                write!(f, "unsupported input manifest schema {found}")
            }
            Self::DuplicatePositivePath => f.write_str("duplicate positive input path"),
            Self::DuplicateEnumerationPath => f.write_str("duplicate directory enumeration path"),
        }
    }
}

impl std::error::Error for InputManifestError {}

fn input_object_encoding(object: &ObjectId) -> Vec<u8> {
    let mut enc = CanonicalEncoder::new();
    let algorithm = match object.0.algorithm {
        DigestAlgorithm::Sha256V1 => 1,
    };
    enc.u32(algorithm)
        .str(object.0.domain)
        .bytes(&object.0.bytes);
    enc.finish()
}

/// Digest the positive manifest as an action-key component, not a CAS object.
/// Fields follow schema declaration order. Positive paths and enumerations are
/// unique and sorted by raw path bytes; directory listings are sets. Approved
/// objects are a membership set sorted by their full canonical identity.
/// Symlink resolution is an ordered chain and is never sorted. V1 file-type
/// tags are regular=1, directory=2, symlink=3; SHA-256 V1 has algorithm tag 1.
pub fn action_input_manifest_digest(
    manifest: &ActionInputManifest,
) -> Result<TypedDigest, InputManifestError> {
    let ActionInputManifest {
        schema_version,
        inputs,
        directory_enumerations,
        approved_generated_objects,
    } = manifest;
    if *schema_version != INPUT_EVIDENCE_SCHEMA_VERSION {
        return Err(InputManifestError::UnsupportedSchema {
            found: *schema_version,
        });
    }
    let mut inputs: Vec<_> = inputs.iter().collect();
    inputs.sort_by(|a, b| a.virtual_path.cmp(&b.virtual_path));
    if inputs
        .windows(2)
        .any(|pair| pair[0].virtual_path == pair[1].virtual_path)
    {
        return Err(InputManifestError::DuplicatePositivePath);
    }
    let mut enumerations: Vec<_> = directory_enumerations.iter().collect();
    enumerations.sort_by(|a, b| a.virtual_path.cmp(&b.virtual_path));
    if enumerations
        .windows(2)
        .any(|pair| pair[0].virtual_path == pair[1].virtual_path)
    {
        return Err(InputManifestError::DuplicateEnumerationPath);
    }
    let mut enc = CanonicalEncoder::new();
    enc.u32(*schema_version).seq(&inputs, |enc, input| {
        let file_type = match input.file_type {
            InputFileType::Regular => 1,
            InputFileType::Directory => 2,
            InputFileType::Symlink => 3,
        };
        enc.bytes(input.virtual_path.as_bytes())
            .bytes(&input_object_encoding(&input.object))
            .u32(file_type)
            .bool(input.executable)
            .seq(&input.symlink_resolution, |enc, hop| {
                enc.bytes(hop.as_bytes());
            });
    });
    enc.seq(&enumerations, |enc, enumeration| {
        let mut entries: Vec<_> = enumeration.entries.iter().collect();
        entries.sort_unstable();
        entries.dedup();
        enc.bytes(enumeration.virtual_path.as_bytes())
            .seq(&entries, |enc, entry| {
                enc.bytes(entry.as_bytes());
            });
    });
    let mut objects: Vec<_> = approved_generated_objects
        .iter()
        .map(input_object_encoding)
        .collect();
    objects.sort_unstable();
    objects.dedup();
    enc.seq(&objects, |enc, object| {
        enc.bytes(object);
    });
    Ok(compute(DOMAIN_ACTION_INPUT_MANIFEST, &enc.finish()))
}

/// Stable canonical tag for each action class (wire-stable; NOT the Rust
/// discriminant — enum reordering must not change keys).
#[must_use]
pub const fn action_class_tag(class: ActionClass) -> u32 {
    match class {
        ActionClass::CargoWholeCommandBounded => 1,
        ActionClass::RustcDependencyCompile => 2,
        ActionClass::RustcWorkspaceCompile => 3,
        ActionClass::RustdocCompile => 4,
        ActionClass::Link => 5,
        ActionClass::BuildScriptCompile => 6,
        ActionClass::BuildScriptRun => 7,
        ActionClass::NativeCompileC => 8,
        ActionClass::NativeCompileCxx => 9,
        ActionClass::NativeArchive => 10,
        ActionClass::BindgenGeneration => 11,
        ActionClass::CodeGeneratorRun => 12,
        ActionClass::NextestTestCase => 13,
        ActionClass::TestBinaryBatch => 14,
        ActionClass::DoctestCompile => 15,
        ActionClass::DoctestRun => 16,
        ActionClass::ClippyCompile => 17,
        ActionClass::BenchmarkCompile => 18,
        ActionClass::BenchmarkRun => 19,
        ActionClass::ToolchainProbe => 20,
        ActionClass::WorkerProbe => 21,
    }
}

/// One breakdown row: component name + its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakdownComponent {
    /// Stable component name (matches A014's component list).
    pub name: &'static str,
    /// The component digest that entered the key.
    pub digest: TypedDigest,
}

/// The structured, redaction-safe key breakdown returned WITH every key.
/// Digests only — raw component values never appear here, so breakdowns
/// are safe to persist in receipts and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionKeyBreakdown {
    /// Key epoch used.
    pub key_epoch: u32,
    /// Projection epoch used.
    pub projection_epoch: u32,
    /// Canonical action-class tag.
    pub action_class_tag: u32,
    /// The twelve components in canonical order.
    pub components: Vec<BreakdownComponent>,
    /// The final action key.
    pub final_key: TypedDigest,
}

/// Compute the action key and its breakdown from a descriptor.
#[must_use]
pub fn compute_action_key(descriptor: &ActionDescriptor) -> ActionKeyBreakdown {
    let components: Vec<BreakdownComponent> = descriptor
        .key_input_components()
        .into_iter()
        .map(|(name, digest)| BreakdownComponent {
            name,
            digest: digest.clone(),
        })
        .collect();
    let mut enc = CanonicalEncoder::new();
    enc.u32(descriptor.key_epoch)
        .u32(descriptor.projection_epoch)
        .u32(action_class_tag(descriptor.action_class));
    for c in &components {
        // Component digests enter as (domain, bytes): the domain string
        // participates so a digest can never be replayed across component
        // slots that happen to share bytes.
        enc.str(c.digest.domain);
        enc.bytes(&c.digest.bytes);
    }
    let final_key = compute(DOMAIN_ACTION_KEY, &enc.finish());
    ActionKeyBreakdown {
        key_epoch: descriptor.key_epoch,
        projection_epoch: descriptor.projection_epoch,
        action_class_tag: action_class_tag(descriptor.action_class),
        components,
        final_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::input_evidence::{DirectoryEnumeration, PositiveInput};
    use rabs_protocol::raw_bytes::RawBytes;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn input_manifest() -> ActionInputManifest {
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: vec![
                PositiveInput {
                    virtual_path: RawBytes::new(b"/workspace/link".to_vec()),
                    object: ObjectId(d("rabs.object.v1", 1)),
                    file_type: InputFileType::Symlink,
                    executable: false,
                    symlink_resolution: vec![
                        RawBytes::new(b"middle".to_vec()),
                        RawBytes::new(b"actual".to_vec()),
                    ],
                },
                PositiveInput {
                    virtual_path: RawBytes::new(b"/workspace/\xff".to_vec()),
                    object: ObjectId(d("rabs.object.v1", 2)),
                    file_type: InputFileType::Regular,
                    executable: true,
                    symlink_resolution: Vec::new(),
                },
            ],
            directory_enumerations: vec![
                DirectoryEnumeration {
                    virtual_path: RawBytes::new(b"/workspace".to_vec()),
                    entries: vec![RawBytes::new(b"link".to_vec()), RawBytes::new(vec![0xff])],
                },
                DirectoryEnumeration {
                    virtual_path: RawBytes::new(b"/empty".to_vec()),
                    entries: Vec::new(),
                },
            ],
            approved_generated_objects: vec![
                ObjectId(d("rabs.object.v1", 3)),
                ObjectId(d("rabs.toolchain-object.v1", 3)),
            ],
        }
    }

    #[test]
    fn input_manifest_identity_ignores_set_order_and_duplicate_membership() {
        let original = input_manifest();
        let mut permuted = original.clone();
        permuted.inputs.reverse();
        permuted.directory_enumerations.reverse();
        for enumeration in &mut permuted.directory_enumerations {
            enumeration.entries.reverse();
            if let Some(entry) = enumeration.entries.first().cloned() {
                enumeration.entries.push(entry);
            }
        }
        permuted.approved_generated_objects.reverse();
        permuted
            .approved_generated_objects
            .push(permuted.approved_generated_objects[0].clone());
        let digest = action_input_manifest_digest(&original).unwrap();
        assert_eq!(digest.domain, DOMAIN_ACTION_INPUT_MANIFEST);
        assert_eq!(digest.algorithm, DigestAlgorithm::Sha256V1);
        assert_eq!(digest, action_input_manifest_digest(&permuted).unwrap());
        // Schema-valid empty evidence is distinct from the populated manifest.
        let empty = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            ..ActionInputManifest::default()
        };
        assert_ne!(digest, action_input_manifest_digest(&empty).unwrap());
    }

    #[test]
    fn input_manifest_identity_binds_all_semantic_fields_and_chain_order() {
        let original = input_manifest();
        let digest = action_input_manifest_digest(&original).unwrap();
        for mutation in 0..14 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.inputs[0].virtual_path = RawBytes::new(b"/other".to_vec()),
                1 => changed.inputs[0].object.0.bytes[0] ^= 1,
                2 => changed.inputs[0].object.0.domain = "rabs.other-object.v1",
                3 => changed.inputs[0].file_type = InputFileType::Regular,
                4 => changed.inputs[0].file_type = InputFileType::Directory,
                5 => changed.inputs[0].executable = true,
                6 => changed.inputs[0].symlink_resolution.reverse(),
                7 => changed.inputs[0].symlink_resolution[0] = RawBytes::new(b"different".to_vec()),
                8 => changed.inputs[0]
                    .symlink_resolution
                    .push(RawBytes::new(b"extra".to_vec())),
                9 => {
                    changed.directory_enumerations[0].virtual_path =
                        RawBytes::new(b"/elsewhere".to_vec())
                }
                10 => changed.directory_enumerations[0]
                    .entries
                    .push(RawBytes::new(b"new".to_vec())),
                11 => changed.approved_generated_objects[0].0.bytes[0] ^= 1,
                12 => changed.approved_generated_objects[0].0.domain = "rabs.changed-object.v1",
                13 => changed.inputs[1].virtual_path = RawBytes::new(b"/workspace/\xfe".to_vec()),
                _ => unreachable!(),
            }
            assert_ne!(
                digest,
                action_input_manifest_digest(&changed).unwrap(),
                "semantic mutation {mutation} must change identity"
            );
        }
    }

    #[test]
    fn input_manifest_rejects_unknown_schema_and_duplicate_paths() {
        for schema in [0, INPUT_EVIDENCE_SCHEMA_VERSION + 1, u32::MAX] {
            let mut manifest = input_manifest();
            manifest.schema_version = schema;
            assert_eq!(
                action_input_manifest_digest(&manifest),
                Err(InputManifestError::UnsupportedSchema { found: schema })
            );
        }
        let mut manifest = input_manifest();
        manifest.inputs.push(manifest.inputs[0].clone());
        assert_eq!(
            action_input_manifest_digest(&manifest),
            Err(InputManifestError::DuplicatePositivePath)
        );
        manifest.inputs.last_mut().unwrap().object.0.bytes[0] ^= 1;
        assert_eq!(
            action_input_manifest_digest(&manifest),
            Err(InputManifestError::DuplicatePositivePath)
        );
        let mut manifest = input_manifest();
        manifest
            .directory_enumerations
            .push(manifest.directory_enumerations[0].clone());
        assert_eq!(
            action_input_manifest_digest(&manifest),
            Err(InputManifestError::DuplicateEnumerationPath)
        );
    }

    fn descriptor() -> ActionDescriptor {
        ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::RustcDependencyCompile,
            normalized_invocation: d("rabs.invocation.v1", 1),
            virtual_working_directory: d("rabs.cwd.v1", 2),
            action_inputs: d("rabs.inputs.v1", 3),
            negative_dependencies: d("rabs.negdeps.v1", 4),
            dependency_inputs: d("rabs.deps.v1", 5),
            toolchain: d("rabs.toolchain.v1", 6),
            output_platform: d("rabs.platform.v1", 7),
            environment: d("rabs.env.v1", 8),
            sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
            build_path_semantic_policy: d("rabs.path-policy.v1", 10),
            execution_semantics: d("rabs.exec-semantics.v1", 11),
            output_declarations: d("rabs.outputs.v1", 12),
        }
    }

    #[test]
    fn identical_descriptors_yield_identical_keys_and_breakdowns() {
        let a = compute_action_key(&descriptor());
        let b = compute_action_key(&descriptor());
        assert_eq!(a, b);
        assert_eq!(a.components.len(), 12);
        assert_eq!(a.final_key.domain, DOMAIN_ACTION_KEY);
    }

    #[test]
    fn every_component_mutation_changes_the_key() {
        // The F015 seed at the assembly layer: perturb each component
        // digest in isolation; the final key must change every time.
        let base = compute_action_key(&descriptor());
        let mutations: Vec<ActionDescriptor> = (0..12)
            .map(|i| {
                let mut m = descriptor();
                let bump = |t: &mut TypedDigest| t.bytes[0] ^= 0xFF;
                match i {
                    0 => bump(&mut m.normalized_invocation),
                    1 => bump(&mut m.virtual_working_directory),
                    2 => bump(&mut m.action_inputs),
                    3 => bump(&mut m.negative_dependencies),
                    4 => bump(&mut m.dependency_inputs),
                    5 => bump(&mut m.toolchain),
                    6 => bump(&mut m.output_platform),
                    7 => bump(&mut m.environment),
                    8 => bump(&mut m.sandbox_semantic_policy),
                    9 => bump(&mut m.build_path_semantic_policy),
                    10 => bump(&mut m.execution_semantics),
                    _ => bump(&mut m.output_declarations),
                }
                m
            })
            .collect();
        for (i, m) in mutations.iter().enumerate() {
            let k = compute_action_key(m);
            assert_ne!(
                k.final_key, base.final_key,
                "mutating component {i} did not change the key"
            );
        }
    }

    #[test]
    fn epochs_and_class_split_the_namespace() {
        let base = compute_action_key(&descriptor());
        let mut k = descriptor();
        k.key_epoch = 2;
        assert_ne!(compute_action_key(&k).final_key, base.final_key);
        let mut p = descriptor();
        p.projection_epoch = 2;
        assert_ne!(compute_action_key(&p).final_key, base.final_key);
        let mut c = descriptor();
        c.action_class = ActionClass::ClippyCompile;
        assert_ne!(compute_action_key(&c).final_key, base.final_key);
    }

    #[test]
    fn class_tags_are_wire_stable_and_unique() {
        // The tag table, not the Rust discriminant, is the wire identity.
        let all = [
            ActionClass::CargoWholeCommandBounded,
            ActionClass::RustcDependencyCompile,
            ActionClass::RustcWorkspaceCompile,
            ActionClass::RustdocCompile,
            ActionClass::Link,
            ActionClass::BuildScriptCompile,
            ActionClass::BuildScriptRun,
            ActionClass::NativeCompileC,
            ActionClass::NativeCompileCxx,
            ActionClass::NativeArchive,
            ActionClass::BindgenGeneration,
            ActionClass::CodeGeneratorRun,
            ActionClass::NextestTestCase,
            ActionClass::TestBinaryBatch,
            ActionClass::DoctestCompile,
            ActionClass::DoctestRun,
            ActionClass::ClippyCompile,
            ActionClass::BenchmarkCompile,
            ActionClass::BenchmarkRun,
            ActionClass::ToolchainProbe,
            ActionClass::WorkerProbe,
        ];
        let mut tags: Vec<u32> = all.iter().map(|c| action_class_tag(*c)).collect();
        let len = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), len, "duplicate class tags");
        assert_eq!(action_class_tag(ActionClass::CargoWholeCommandBounded), 1);
        assert_eq!(action_class_tag(ActionClass::WorkerProbe), 21);
    }

    #[test]
    fn breakdown_carries_digests_only() {
        // Redaction safety: the breakdown's Debug dump contains component
        // names and hex-ish digest bytes, never raw values (there is no
        // field that COULD hold one — assert the shape).
        let b = compute_action_key(&descriptor());
        for c in &b.components {
            assert!(!c.name.is_empty());
            assert_eq!(c.digest.bytes.len(), 32);
        }
    }
}
