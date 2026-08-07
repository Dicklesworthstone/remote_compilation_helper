//! Output declaration digest (bead F011; plan §66; invariant I4's output
//! half; risk R7).
//!
//! What an action is EXPECTED to produce is part of what the action *is*:
//! two invocations identical in every input but declaring different
//! outputs (`--emit=metadata` vs `--emit=metadata,link` materialized as
//! different logical output sets) are different actions. The declaration
//! digest covers **logical classes and virtual paths only** — where the
//! bytes will physically be staged on any particular worker or edge is a
//! placement decision and is structurally absent from the declaration
//! type: there is no field to put a staging path in.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the output-declaration set.
pub const DOMAIN_OUTPUT_DECLARATIONS: &str = "rabs.output-declarations.v1";

/// Logical output classes (plan §66; wire-stable tags in `class_tag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum OutputClass {
    File,
    Tree,
    Symlink,
    Executable,
    Diagnostics,
    DepInfo,
    BuildScriptMetadata,
    ProvisionalMetadata,
}

/// Wire-stable class tag (enum reordering cannot silently re-key).
#[must_use]
pub const fn class_tag(class: OutputClass) -> u32 {
    match class {
        OutputClass::File => 1,
        OutputClass::Tree => 2,
        OutputClass::Symlink => 3,
        OutputClass::Executable => 4,
        OutputClass::Diagnostics => 5,
        OutputClass::DepInfo => 6,
        OutputClass::BuildScriptMetadata => 7,
        OutputClass::ProvisionalMetadata => 8,
    }
}

/// One declared logical output: a class plus its VIRTUAL path (canonical
/// execroot form). Physical staging locations are unrepresentable here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputDeclaration {
    /// Virtual path in canonical execroot form (`/__rabs/...`).
    pub virtual_path: String,
    /// Logical class of the output at that path.
    pub class: OutputClass,
    /// Whether the action may legitimately omit this output (e.g.
    /// dep-info under certain emit combinations). Optionality is part
    /// of the declaration semantics.
    pub optional: bool,
}

/// The declared output set for one action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutputDeclarationSet {
    /// Declarations in any construction order (hashed as a sorted set).
    pub declarations: Vec<OutputDeclaration>,
}

/// Declaration-set canonicalization failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationError {
    /// Two declarations name the same virtual path — ambiguous.
    DuplicateVirtualPath(String),
}

impl OutputDeclarationSet {
    /// Canonical bytes: sorted by virtual path (a set, not a sequence —
    /// declaration order is not semantics), duplicate paths rejected.
    ///
    /// # Errors
    /// [`DeclarationError::DuplicateVirtualPath`] on ambiguity.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeclarationError> {
        let mut sorted = self.declarations.clone();
        sorted.sort();
        for w in sorted.windows(2) {
            if w[0].virtual_path == w[1].virtual_path {
                return Err(DeclarationError::DuplicateVirtualPath(
                    w[0].virtual_path.clone(),
                ));
            }
        }
        let mut enc = CanonicalEncoder::new();
        enc.u64(sorted.len() as u64);
        for d in &sorted {
            enc.str(&d.virtual_path)
                .u32(class_tag(d.class))
                .bool(d.optional);
        }
        Ok(enc.finish())
    }

    /// The declaration digest — the descriptor's `output_declarations`
    /// slot.
    ///
    /// # Errors
    /// Propagates [`DeclarationError`].
    pub fn declaration_digest(&self) -> Result<TypedDigest, DeclarationError> {
        Ok(compute(
            DOMAIN_OUTPUT_DECLARATIONS,
            &self.canonical_bytes()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(path: &str, class: OutputClass) -> OutputDeclaration {
        OutputDeclaration {
            virtual_path: path.into(),
            class,
            optional: false,
        }
    }

    fn set() -> OutputDeclarationSet {
        OutputDeclarationSet {
            declarations: vec![
                decl("/__rabs/out/libserde.rmeta", OutputClass::File),
                decl("/__rabs/out/libserde.rlib", OutputClass::File),
                decl("/__rabs/out/serde.d", OutputClass::DepInfo),
            ],
        }
    }

    fn digest_of(s: &OutputDeclarationSet) -> TypedDigest {
        s.declaration_digest().unwrap()
    }

    #[test]
    fn declaration_changes_change_the_key() {
        let base = digest_of(&set());
        // Added output.
        let mut m = set();
        m.declarations.push(decl(
            "/__rabs/out/serde-diag.json",
            OutputClass::Diagnostics,
        ));
        assert_ne!(base, digest_of(&m));
        // Removed output.
        let mut m = set();
        m.declarations.pop();
        assert_ne!(base, digest_of(&m));
        // Same path, different class.
        let mut m = set();
        m.declarations[0].class = OutputClass::Tree;
        assert_ne!(base, digest_of(&m));
        // Same path+class, different optionality.
        let mut m = set();
        m.declarations[2].optional = true;
        assert_ne!(base, digest_of(&m));
        // Different virtual path.
        let mut m = set();
        m.declarations[0].virtual_path = "/__rabs/out/libserde2.rmeta".into();
        assert_ne!(base, digest_of(&m));
    }

    #[test]
    fn physical_staging_locations_are_unrepresentable() {
        // The acceptance's second half, made structural: the declaration
        // type has no staging-path field, so "physical path change does
        // not change the key" is true by construction. This destructure
        // is the tripwire — adding any physical/staging field to the
        // declaration forces a compile error here and a keying decision.
        let OutputDeclaration {
            virtual_path: _,
            class: _,
            optional: _,
        } = decl("/__rabs/out/x", OutputClass::File);
    }

    #[test]
    fn declarations_are_a_set_with_unique_paths() {
        // Construction order never forks the digest…
        let mut reordered = set();
        reordered.declarations.reverse();
        assert_eq!(digest_of(&set()), digest_of(&reordered));
        // …and duplicate virtual paths are a typed ambiguity error.
        let mut dup = set();
        dup.declarations
            .push(decl("/__rabs/out/serde.d", OutputClass::File));
        assert!(matches!(
            dup.canonical_bytes(),
            Err(DeclarationError::DuplicateVirtualPath(_))
        ));
    }

    #[test]
    fn class_tags_are_wire_stable_and_distinct() {
        let all = [
            OutputClass::File,
            OutputClass::Tree,
            OutputClass::Symlink,
            OutputClass::Executable,
            OutputClass::Diagnostics,
            OutputClass::DepInfo,
            OutputClass::BuildScriptMetadata,
            OutputClass::ProvisionalMetadata,
        ];
        let mut tags: Vec<u32> = all.iter().map(|c| class_tag(*c)).collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5, 6, 7, 8], "pinned wire tags");
        tags.dedup();
        assert_eq!(tags.len(), all.len());
    }
}
