//! Ordered link-input hashing + linker response/script normalization
//! (beads L002 + L003; plan §97; risks R11/R84).
//!
//! The cores live in L001 (link parser), F005 (response files), and
//! F009 (ordered link inputs); this suite proves the two beads'
//! acceptance lines END TO END through those pieces together:
//!
//! - L002: link inputs are ORDER-SENSITIVE and every consumed
//!   artifact hashes exactly — reorder changes the key, content
//!   change changes the key, LTO components enter individually;
//! - L003: linker response files normalize by content + semantic
//!   position (temp filenames vanish), and linker scripts are
//!   content inputs.

use rabs_key::dependency_identity::{ConsumedArtifact, DependencyInputs};
use rabs_key::link_invocation::{DriverStyle, parse_link};
use rabs_key::response_files::{
    NormalizedArg, canonical_bytes as response_bytes, normalize_response_files,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn identify_file(path: &str) -> Option<ObjectId> {
    match path {
        "a.o" => Some(ObjectId(d("rabs.object.v1", 1))),
        "b.o" => Some(ObjectId(d("rabs.object.v1", 2))),
        "a-changed.o" => Some(ObjectId(d("rabs.object.v1", 9))),
        _ => None,
    }
}

fn identify_script(path: &str) -> Option<TypedDigest> {
    match path {
        "layout.ld" => Some(d("rabs.linker-script.v1", 3)),
        "layout-changed.ld" => Some(d("rabs.linker-script.v1", 4)),
        _ => None,
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn l002_reorder_changes_key_and_content_change_changes_key() {
    // Through the L001 parser…
    let linker = d("rabs.tool-binary.v1", 7);
    let forward = parse_link(
        DriverStyle::DirectLinker,
        linker.clone(),
        &args(&["a.o", "b.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();
    let reordered = parse_link(
        DriverStyle::DirectLinker,
        linker.clone(),
        &args(&["b.o", "a.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();
    assert_ne!(
        forward.invocation_digest(),
        reordered.invocation_digest(),
        "L002: link input order is semantics"
    );
    let content_changed = parse_link(
        DriverStyle::DirectLinker,
        linker,
        &args(&["a-changed.o", "b.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();
    assert_ne!(
        forward.invocation_digest(),
        content_changed.invocation_digest(),
        "L002: consumed-byte change is semantics"
    );
    // …and through the F009 dependency-input sequence, including LTO
    // components entering individually.
    let lto_two = DependencyInputs {
        link_inputs: vec![
            ConsumedArtifact::LtoComponent(d("rabs.dep-artifact.v1", 1)),
            ConsumedArtifact::LtoComponent(d("rabs.dep-artifact.v1", 2)),
        ],
        ..Default::default()
    };
    let lto_reordered = DependencyInputs {
        link_inputs: vec![
            ConsumedArtifact::LtoComponent(d("rabs.dep-artifact.v1", 2)),
            ConsumedArtifact::LtoComponent(d("rabs.dep-artifact.v1", 1)),
        ],
        ..Default::default()
    };
    assert_ne!(lto_two.inputs_digest(), lto_reordered.inputs_digest());
}

#[test]
fn l003_linker_response_files_and_scripts_normalize_by_content() {
    // Linker response files: identical CONTENT under two temp names
    // normalizes identically at the same semantic position.
    let read = |path: &str| match path {
        "/tmp/linkXXXX/rsp" | "/tmp/other/rsp" => Some(b"a.o\nb.o\n--gc-sections\n".to_vec()),
        _ => None,
    };
    let via_first =
        normalize_response_files(&args(&["ld.lld", "@/tmp/linkXXXX/rsp"]), read).unwrap();
    let via_second = normalize_response_files(&args(&["ld.lld", "@/tmp/other/rsp"]), read).unwrap();
    assert_eq!(
        response_bytes(&via_first),
        response_bytes(&via_second),
        "L003: temp response filenames vanish; content keys"
    );
    assert!(matches!(via_first[1], NormalizedArg::ResponseExpansion(_)));
    // Linker scripts are CONTENT inputs: a changed script forks the
    // link key even with identical objects and flags.
    let linker = d("rabs.tool-binary.v1", 7);
    let with_script = parse_link(
        DriverStyle::DirectLinker,
        linker.clone(),
        &args(&["-T", "layout.ld", "a.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();
    let script_changed = parse_link(
        DriverStyle::DirectLinker,
        linker,
        &args(&["-T", "layout-changed.ld", "a.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();
    assert_ne!(
        with_script.invocation_digest(),
        script_changed.invocation_digest(),
        "L003: script content is a link input"
    );
}
