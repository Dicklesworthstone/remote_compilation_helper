//! Local-only preparation of one root or an explicit multi-repository closure.
//!
//! source_roots maps stable workspace directory names to {path, files}. Relative
//! host paths resolve against --worker-prepare's source root; absolute paths are
//! explicit access to another checkout. All roots are captured in ONE paired
//! closure scan. Host paths are consumed locally and never enter request.json.
//! Manual modes select explicit files. cargo_source resolves a locked local Cargo
//! graph from a retained anchor through the bounded planner below. None of these
//! modes authorizes an action-cache hit.

mod cargo;

use super::{MAX_SOURCE_ROOTS, SourceUpload, invalid, manifest_value, require, valid_closure_root};
use rabs_sandbox::snapshot_capture::{
    MemberDisposition, capture_sealed_source, member_disposition,
};
use rabs_sandbox::source_transfer::{
    MAX_SOURCE_BYTES, MAX_SOURCE_FILES, SourceFile, SourceManifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct SourcePreparation {
    roots: Vec<(String, PathBuf)>,
    selections: Vec<(String, Vec<String>)>,
    closure: bool,
    cargo: Option<cargo::CargoSource>,
}

fn selected_files(value: &Value) -> io::Result<Vec<String>> {
    let files = value
        .as_array()
        .filter(|files| !files.is_empty() && files.len() <= MAX_SOURCE_FILES)
        .ok_or_else(|| invalid("selected source files must be a nonempty bounded array"))?;
    files
        .iter()
        .map(|file| {
            file.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("selected source files must be relative path strings"))
        })
        .collect()
}

fn local_root(base: &Path, value: &Value) -> io::Result<PathBuf> {
    let path = value
        .as_str()
        .filter(|path| !path.is_empty() && path.len() <= 4096)
        .ok_or_else(|| invalid("source root path must be a bounded nonempty string"))?;
    if path == "." {
        return Ok(base.to_path_buf());
    }
    require(
        !path.contains(['\\', ':'])
            && !path.chars().any(char::is_control)
            && path
                .strip_prefix('/')
                .unwrap_or(path)
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
        "source root path must be unambiguous without traversal",
    )?;
    Ok(base.join(path))
}

impl SourcePreparation {
    pub(super) fn parse(base: &Path, specification: &Value) -> io::Result<Self> {
        require(base.is_absolute(), "source root must be absolute")?;
        require(
            specification.is_object(),
            "source preparation requires an object",
        )?;
        require(
            specification["kind"] == "canonical-exec"
                && specification["request_id"].as_u64().is_some(),
            "source preparation requires canonical-exec and an unsigned request_id",
        )?;
        require(
            specification.get("source_manifest").is_none()
                && specification.get("workspace_backing").is_none(),
            "preparation cannot replace an existing source_manifest or workspace_backing",
        )?;
        require(
            serde_json::to_vec(specification)?.len() <= super::MAX_FRAME_BYTES,
            "source preparation specification exceeds the request bound",
        )?;

        let mut roots = Vec::new();
        let mut selections = Vec::new();
        let cargo = specification
            .get("cargo_source")
            .map(cargo::CargoSource::parse)
            .transpose()?;
        let closure = specification.get("source_roots").is_some();
        if let Some(cargo) = &cargo {
            require(
                !closure && specification.get("source_files").is_none(),
                "cargo_source, source_roots and source_files are mutually exclusive",
            )?;
            roots.push(("workspace".to_owned(), base.to_path_buf()));
            selections.push(("workspace".to_owned(), vec![cargo.manifest().to_owned()]));
        } else if closure {
            require(
                specification.get("source_files").is_none(),
                "source_roots and source_files are mutually exclusive",
            )?;
            let declared = specification["source_roots"]
                .as_object()
                .filter(|roots| !roots.is_empty() && roots.len() <= MAX_SOURCE_ROOTS)
                .ok_or_else(|| invalid("source_roots must be a nonempty bounded object"))?;
            let mut names = BTreeSet::new();
            let mut count = 0_usize;
            for (name, entry) in declared {
                require(
                    valid_closure_root(name) && names.insert(name.to_ascii_lowercase()),
                    "unsafe, hidden or case-colliding source root name",
                )?;
                require(
                    entry.as_object().is_some_and(|fields| fields.len() == 2),
                    "source root requires exactly path and files",
                )?;
                let root = local_root(base, &entry["path"])?;
                let files = selected_files(&entry["files"])?;
                count = count
                    .checked_add(files.len())
                    .filter(|count| *count <= MAX_SOURCE_FILES)
                    .ok_or_else(|| invalid("source closure exceeds aggregate file count"))?;
                roots.push((name.clone(), root));
                selections.push((name.clone(), files));
            }
        } else {
            roots.push(("workspace".to_owned(), base.to_path_buf()));
            selections.push((
                "workspace".to_owned(),
                selected_files(&specification["source_files"])?,
            ));
        }

        // Validate the full destination namespace and all command fields before
        // opening any checkout. Empty-content descriptors are LOCAL preflight
        // probes only, never persisted, transmitted or used as source evidence.
        let mut probe_files = Vec::new();
        for (name, files) in &selections {
            for relative in files {
                for path in std::iter::once(relative.as_str())
                    .chain(relative.match_indices('/').map(|(end, _)| &relative[..end]))
                {
                    require(
                        member_disposition(path, false) == MemberDisposition::Include,
                        "selected source path is excluded by capture policy",
                    )?;
                }
                let path = if closure {
                    format!("{name}/{relative}")
                } else {
                    relative.clone()
                };
                require(
                    member_disposition(&path, false) == MemberDisposition::Include,
                    "projected source path is excluded by capture policy",
                )?;
                probe_files.push(SourceFile {
                    path,
                    len: 0,
                    sha256: Sha256::digest([]).into(),
                    executable: false,
                });
            }
        }
        let probe_manifest = SourceManifest::new(probe_files)?;
        let mut probe_request = specification.clone();
        let fields = probe_request
            .as_object_mut()
            .ok_or_else(|| invalid("source preparation object"))?;
        fields.remove("source_files");
        fields.remove("source_roots");
        fields.remove("cargo_source");
        fields.insert(
            "source_manifest".to_owned(),
            manifest_value(&probe_manifest),
        );
        super::validate_request(&probe_request)?;
        Ok(Self {
            roots,
            selections,
            closure,
            cargo,
        })
    }

    pub(super) fn root_count(&self) -> usize {
        self.roots.len()
    }

    pub(super) fn capture(&self) -> io::Result<SourceUpload> {
        // Never capture roots independently and merge them afterward. The scanner
        // compares a complete first closure pass with a complete second pass and
        // retries the ENTIRE closure on mutation. Its byte budget is global.
        let image = Arc::new(
            capture_sealed_source(&self.roots, false, 2, MAX_SOURCE_BYTES)
                .map_err(|error| invalid(&format!("source closure capture refused: {error:?}")))?,
        );
        if let Some(cargo) = &self.cargo {
            cargo.prepare(image)
        } else if self.closure {
            SourceUpload::from_snapshot_closure(image, &self.selections)
        } else {
            let (root, files) = self
                .selections
                .first()
                .ok_or_else(|| invalid("source preparation has no selection"))?;
            SourceUpload::from_snapshot(image, root, files)
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::coord::source_delivery::{prepare_source_bundle, request_manifest};
    use serde_json::json;
    use std::fs;

    fn specification(dep: &Path) -> Value {
        json!({"kind":"canonical-exec", "request_id":71, "program":"cargo",
            "args":["build", "--locked", "--offline"], "toolchain_backing":"/tc",
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace/app",
                "env":{"CARGO_TARGET_DIR":"/__rabs/out/build", "BUILD_LABEL":"exact\n雪"}},
            "source_roots":{
                "app":{"path":".", "files":["Cargo.toml", "src/lib.rs"]},
                "dep":{"path":dep, "files":["Cargo.toml", "src/lib.rs"]}},
            "extension":{"keep":"exactly"}})
    }

    fn checkouts(app: &Path, dep: &Path) {
        for root in [app, dep] {
            fs::create_dir(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
            fs::write(root.join("not-selected.private"), b"never uploaded").unwrap();
        }
        fs::write(
            app.join("Cargo.toml"),
            b"[dependencies]\ndep = { path = \"../dep\" }\n",
        )
        .unwrap();
        fs::write(
            dep.join("Cargo.toml"),
            b"[package]\nname = \"dep\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
    }

    #[test]
    fn closure_preparation_preserves_paths_fields_and_replay_without_original_checkouts() {
        let app = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        checkouts(app.path(), dep.path());
        let spec = specification(dep.path());
        let original = spec.clone();
        let owner = tempfile::tempdir().unwrap();
        let bundle = owner.path().join("bundle");
        let prepared = prepare_source_bundle(app.path(), &spec, &bundle).unwrap();
        assert_eq!(spec, original);
        assert_eq!(prepared["source_roots"], 2);
        assert_eq!(prepared["source_files"], 4);
        assert_eq!(prepared["executed"], false);
        assert_eq!(prepared["publication_authorized"], false);
        let bytes = fs::read(bundle.join("request.json")).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(request.get("source_roots").is_none());
        assert!(request.get("source_files").is_none());
        assert!(!request.to_string().contains(dep.path().to_str().unwrap()));
        assert_eq!(request["command_context"], spec["command_context"]);
        let mut actual = request.clone();
        actual.as_object_mut().unwrap().remove("source_manifest");
        let mut expected = spec;
        expected.as_object_mut().unwrap().remove("source_roots");
        assert_eq!(actual, expected);
        let source = bundle.join("source");
        assert_eq!(
            fs::read(source.join("app/Cargo.toml")).unwrap(),
            fs::read(app.path().join("Cargo.toml")).unwrap()
        );
        for name in ["app", "dep"] {
            assert!(!source.join(name).join("not-selected.private").exists());
        }
        fs::rename(app.path().join("src"), app.path().join("old-src")).unwrap();
        fs::rename(dep.path().join("src"), dep.path().join("old-src")).unwrap();
        let image = Arc::new(
            capture_sealed_source(&[("workspace".into(), source)], false, 2, 200_000).unwrap(),
        );
        let upload = SourceUpload::for_request(image, "workspace", &request).unwrap();
        assert_eq!(upload.wire_manifest(), request["source_manifest"]);
        assert_eq!(
            request_manifest(&request).unwrap().unwrap().files().len(),
            4
        );
    }

    #[test]
    fn declaration_validation_precedes_filesystem_access() {
        let base = Path::new("/definitely-not-present-rabs-source");
        let good = specification(Path::new("/also-not-present-rabs-dep"));
        let mut bad = Vec::new();
        for (field, value) in [
            ("source_roots", Value::Null),
            ("source_roots", json!([])),
            ("source_roots", json!({})),
            ("source_files", json!(["lib.rs"])),
            ("workspace_backing", json!("/ws")),
            ("source_manifest", Value::Null),
        ] {
            let mut spec = good.clone();
            spec[field] = value;
            bad.push(spec);
        }
        for (field, value) in [
            ("path", json!("../escape")),
            ("path", json!("x//y")),
            ("path", json!("/tmp/../other")),
            ("path", json!("/")),
            ("path", json!(false)),
            ("files", json!([])),
            ("files", json!(["../escape"])),
            ("files", json!(["src/lib.rs", "src/lib.rs"])),
            ("files", json!(["src", "src/lib.rs"])),
            ("files", json!(["target/a"])),
            ("files", json!([".git/config"])),
            ("extra", json!(true)),
        ] {
            let mut spec = good.clone();
            spec["source_roots"]["dep"][field] = value;
            bad.push(spec);
        }
        for name in ["target", ".git", "a/b", "..", "app"] {
            let mut spec = good.clone();
            let entry = spec["source_roots"]
                .as_object_mut()
                .unwrap()
                .remove("dep")
                .unwrap();
            spec["source_roots"][if name == "app" { "APP" } else { name }] = entry;
            bad.push(spec);
        }
        for spec in bad {
            assert!(SourcePreparation::parse(base, &spec).is_err(), "{spec}");
        }
        let mut spec = good;
        spec["command_context"]["env"]["HOME"] = json!("never-echo-secret-value");
        let error = SourcePreparation::parse(base, &spec)
            .unwrap_err()
            .to_string();
        assert!(error.contains("worker-owned"));
        assert!(!error.contains("never-echo-secret-value"));
    }

    #[test]
    fn relative_roots_and_root_and_file_count_limits_are_explicit() {
        let base = Path::new("/source-base");
        let mut spec = specification(Path::new("libs/dep"));
        let plan = SourcePreparation::parse(base, &spec).unwrap();
        assert_eq!(
            plan.roots,
            vec![
                ("app".into(), base.to_path_buf()),
                ("dep".into(), base.join("libs/dep"))
            ]
        );
        let roots: serde_json::Map<String, Value> = (0..MAX_SOURCE_ROOTS)
            .map(|index| (format!("r{index}"), json!({"path":".", "files":["lib.rs"]})))
            .collect();
        spec["source_roots"] = Value::Object(roots);
        assert_eq!(
            SourcePreparation::parse(base, &spec).unwrap().root_count(),
            MAX_SOURCE_ROOTS
        );
        spec["source_roots"]["overflow"] = json!({"path":".", "files":["lib.rs"]});
        assert!(SourcePreparation::parse(base, &spec).is_err());
        let files: Vec<_> = (0..MAX_SOURCE_FILES / 2)
            .map(|index| format!("f{index}"))
            .collect();
        spec["source_roots"] =
            json!({"app":{"path":".","files":files}, "dep":{"path":"libs/dep","files":files}});
        SourcePreparation::parse(base, &spec).unwrap();
        spec["source_roots"]["dep"]["files"]
            .as_array_mut()
            .unwrap()
            .push(json!("one-more"));
        assert!(SourcePreparation::parse(base, &spec).is_err());
    }

    #[test]
    fn missing_or_nonregular_dependency_never_creates_a_partial_bundle() {
        let app = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        checkouts(app.path(), dep.path());
        std::os::unix::fs::symlink("src/lib.rs", dep.path().join("alias")).unwrap();
        let owner = tempfile::tempdir().unwrap();
        for case in 0..3 {
            let mut spec = specification(dep.path());
            match case {
                0 => spec["source_roots"]["dep"]["path"] = json!(dep.path().join("missing")),
                1 => spec["source_roots"]["dep"]["files"] = json!(["missing.rs"]),
                _ => spec["source_roots"]["dep"]["files"] = json!(["alias"]),
            }
            let destination = owner.path().join(format!("bundle-{case}"));
            assert!(prepare_source_bundle(app.path(), &spec, &destination).is_err());
            assert!(!destination.exists());
        }
    }

    #[test]
    fn unresolved_root_declarations_are_never_execution_requests() {
        let app = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        checkouts(app.path(), dep.path());
        let owner = tempfile::tempdir().unwrap();
        let bundle = owner.path().join("bundle");
        let spec = specification(dep.path());
        prepare_source_bundle(app.path(), &spec, &bundle).unwrap();
        let request: Value =
            serde_json::from_slice(&fs::read(bundle.join("request.json")).unwrap()).unwrap();
        for with_manifest in [true, false] {
            let mut request = request.clone();
            request["source_roots"] = spec["source_roots"].clone();
            if !with_manifest {
                request.as_object_mut().unwrap().remove("source_manifest");
                request["workspace_backing"] = json!("/ws");
            }
            assert!(crate::coord::worker_delivery::validate_request(&request).is_err());
        }
    }

    #[test]
    fn dependency_change_changes_saved_identity_without_replacing_the_old_bundle() {
        let app = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        checkouts(app.path(), dep.path());
        let owner = tempfile::tempdir().unwrap();
        let first = owner.path().join("first");
        let spec = specification(dep.path());
        let before = prepare_source_bundle(app.path(), &spec, &first).unwrap();
        let old_request = fs::read(first.join("request.json")).unwrap();
        fs::write(
            dep.path().join("src/lib.rs"),
            b"pub fn answer() -> u32 { 99 }\n",
        )
        .unwrap();
        let after = prepare_source_bundle(app.path(), &spec, &owner.path().join("second")).unwrap();
        assert_ne!(before["manifest_sha256"], after["manifest_sha256"]);
        assert_ne!(before["request_sha256"], after["request_sha256"]);
        assert_eq!(
            prepare_source_bundle(app.path(), &spec, &first)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(first.join("request.json")).unwrap(), old_request);
        assert_eq!(
            fs::read(first.join("source/dep/src/lib.rs")).unwrap(),
            b"pub fn answer() -> u32 { 42 }\n"
        );
    }
}
