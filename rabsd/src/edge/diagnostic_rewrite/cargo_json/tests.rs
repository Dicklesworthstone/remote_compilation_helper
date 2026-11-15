use super::super::MappingEntry;
use super::*;
use serde_json::json;

fn mapping(source: &str) -> SubscriberMapping {
    SubscriberMapping::new(vec![
        MappingEntry {
            canonical: "/__rabs/workspace".into(),
            worktree: source.into(),
        },
        MappingEntry {
            canonical: "/__rabs/toolchain".into(),
            worktree: "/opt/rust".into(),
        },
        MappingEntry {
            canonical: "/__rabs/cargo-home".into(),
            worktree: "/home/test/.cargo".into(),
        },
        MappingEntry {
            canonical: OUTPUT_ROOT.into(),
            worktree: "/home/test/results/current".into(),
        },
    ])
    .unwrap()
}

fn presentation(files: Option<&[&str]>) -> CargoJsonPresentation {
    CargoJsonPresentation::new(
        mapping("/home/test/project"),
        files.map(|files| files.iter().map(|file| (*file).into()).collect()),
    )
}

fn artifact() -> Value {
    json!({
        "reason":"compiler-artifact",
        "package_id":"path+file:///__rabs/workspace#fixture@0.1.0",
        "manifest_path":"/__rabs/workspace/Cargo.toml",
        "target":{"kind":["bin"], "src_path":"/__rabs/workspace/src/main.rs", "name":"fixture"},
        "profile":{"test":false}, "features":[], "fresh":false,
        "filenames":["/__rabs/out/cargo/debug/fixture"],
        "executable":"/__rabs/out/cargo/debug/fixture"
    })
}

fn diagnostic() -> Value {
    json!({
        "reason":"compiler-message",
        "package_id":"path+file:///__rabs/workspace#fixture@0.1.0",
        "manifest_path":"/__rabs/workspace/Cargo.toml",
        "target":{"kind":["bin"], "src_path":"/__rabs/workspace/src/main.rs"},
        "message":{
            "$message_type":"diagnostic", "level":"error",
            "message":"literal /__rabs/workspace/message must remain unchanged",
            "code":{"code":"E0123", "explanation":"example /__rabs/workspace/code"},
            "spans":[{
                "file_name":"/__rabs/workspace/src/main.rs", "line_start":7, "column_start":2,
                "line_end":7, "column_end":5, "is_primary":true,
                "text":[{"text":"let p = \"/__rabs/workspace/literal\";", "highlight_start":2, "highlight_end":5}],
                "label":"path /__rabs/workspace/label",
                "suggested_replacement":"\"/__rabs/workspace/replacement\"",
                "expansion":{
                    "span":{"file_name":"/__rabs/workspace/src/macro.rs", "line_start":3, "column_start":1},
                    "macro_decl_name":"keep /__rabs/workspace/macro",
                    "def_site_span":{"file_name":"/__rabs/toolchain/lib/core.rs", "line_start":8, "column_start":1}
                }
            }],
            "children":[{"message":"literal /__rabs/workspace/child", "level":"note", "spans":[], "children":[], "rendered":null}],
            "rendered":"error: literal /__rabs/workspace/message must remain unchanged\n --> /__rabs/workspace/src/main.rs:7:2\n7 | let p = \"/__rabs/workspace/literal\";\n ::: /__rabs/toolchain/lib/core.rs:8:1\n"
        }
    })
}

fn line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn copy(presentation: &CargoJsonPresentation, bytes: &[u8]) -> (CargoPresentationOutcome, Vec<u8>) {
    let mut output = Vec::new();
    let result = presentation
        .copy(bytes, &mut output, u64::MAX, || Ok(()))
        .unwrap();
    (result, output)
}

#[test]
fn returned_artifact_paths_name_only_verified_installed_files() {
    let original = artifact();
    let (outcome, bytes) = copy(&presentation(Some(&["debug/fixture"])), &line(&original));
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        output["filenames"][0],
        "/home/test/results/current/debug/fixture"
    );
    assert_eq!(
        output["executable"],
        "/home/test/results/current/debug/fixture"
    );
    assert_eq!(output["manifest_path"], "/home/test/project/Cargo.toml");
    assert_eq!(
        output["target"]["src_path"],
        "/home/test/project/src/main.rs"
    );
    assert_eq!(output["package_id"], original["package_id"]);
    for files in [None, Some(["debug/different"].as_slice())] {
        let (outcome, output) = copy(&presentation(files), &line(&original));
        assert_eq!(
            outcome,
            CargoPresentationOutcome::Bypass(CargoPresentationBypass::UnavailableOutput)
        );
        assert!(
            output.is_empty(),
            "an incomplete record must never be emitted"
        );
    }
}

#[test]
fn diagnostic_translation_preserves_messages_snippets_suggestions_and_identity() {
    let original = diagnostic();
    let (outcome, bytes) = copy(&presentation(None), &line(&original));
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(output["package_id"], original["package_id"]);
    for field in ["message", "code", "children"] {
        assert_eq!(output["message"][field], original["message"][field]);
    }
    for field in ["text", "label", "suggested_replacement"] {
        assert_eq!(
            output["message"]["spans"][0][field],
            original["message"]["spans"][0][field]
        );
    }
    let span = &output["message"]["spans"][0];
    assert_eq!(span["file_name"], "/home/test/project/src/main.rs");
    assert_eq!(
        span["expansion"]["span"]["file_name"],
        "/home/test/project/src/macro.rs"
    );
    assert_eq!(
        span["expansion"]["def_site_span"]["file_name"],
        "/opt/rust/lib/core.rs"
    );
    assert_eq!(
        span["expansion"]["macro_decl_name"],
        original["message"]["spans"][0]["expansion"]["macro_decl_name"]
    );
    assert_eq!(
        output["message"]["rendered"],
        "error: literal /__rabs/workspace/message must remain unchanged\n --> /home/test/project/src/main.rs:7:2\n7 | let p = \"/__rabs/workspace/literal\";\n ::: /opt/rust/lib/core.rs:8:1\n"
    );
}

#[test]
fn source_only_variant_handles_failed_builds_with_uninstalled_dependency_artifacts() {
    let presenter = CargoJsonPresentation::source_paths(mapping("/home/test/project"));
    let build_script = b"{ \"reason\":\"build-script-executed\", \"out_dir\":\"/__rabs/out/cargo/debug/build/p/out\" }\r\n";
    let mut bytes = line(&artifact());
    bytes.extend_from_slice(build_script);
    bytes.extend(line(&diagnostic()));
    bytes.extend(line(&json!({"reason":"build-finished", "success":false})));
    let (outcome, output) = copy(&presenter, &bytes);
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let records: Vec<_> = output.split_inclusive(|byte| *byte == b'\n').collect();
    let translated_artifact: Value = serde_json::from_slice(records[0]).unwrap();
    assert_eq!(translated_artifact["filenames"], artifact()["filenames"]);
    assert_eq!(translated_artifact["executable"], artifact()["executable"]);
    assert_eq!(
        translated_artifact["target"]["src_path"],
        "/home/test/project/src/main.rs"
    );
    assert_eq!(records[1], build_script);
    let translated_error: Value = serde_json::from_slice(records[2]).unwrap();
    assert_eq!(
        translated_error["message"]["spans"][0]["file_name"],
        "/home/test/project/src/main.rs"
    );
}

#[test]
fn build_script_paths_require_actual_directories_and_keep_nonpath_values() {
    let original = json!({
        "reason":"build-script-executed", "package_id":"path+file:///__rabs/workspace#build@0.1.0",
        "out_dir":"/__rabs/out/cargo/debug/build/build/out",
        "linked_paths":["native=/__rabs/out/cargo/debug/build/build/out", "/__rabs/cargo-home/native", "native=/usr/lib"],
        "linked_libs":["static=library"], "cfgs":["example=\"/__rabs/workspace/cfg\""],
        "env":[["LITERAL", "/__rabs/workspace/value"]]
    });
    let presenter = presentation(Some(&["debug/build/build/out/liblibrary.a"]));
    let (outcome, bytes) = copy(&presenter, &line(&original));
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        output["out_dir"],
        "/home/test/results/current/debug/build/build/out"
    );
    assert_eq!(
        output["linked_paths"][0],
        "native=/home/test/results/current/debug/build/build/out"
    );
    assert_eq!(output["linked_paths"][1], "/home/test/.cargo/native");
    assert_eq!(output["linked_paths"][2], "native=/usr/lib");
    for field in ["package_id", "linked_libs", "cfgs", "env"] {
        assert_eq!(output[field], original[field]);
    }
    let mut absent = original.clone();
    absent["out_dir"] = json!("/__rabs/out/cargo/debug/build/build/empty");
    assert_eq!(
        copy(&presenter, &line(&absent)).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::UnavailableOutput)
    );
    absent = original;
    absent["linked_paths"][0] = json!("unknown=/__rabs/out/cargo/debug/build/build/out");
    assert_eq!(
        copy(&presenter, &line(&absent)).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::InvalidRecord)
    );
}

#[test]
fn component_boundaries_traversal_and_inserted_canonical_names_are_not_guessed() {
    for (path, expected) in [
        (
            "/__rabs/workspace-other/src/main.rs",
            CargoPresentationBypass::UnmappedPath,
        ),
        (
            "/__rabs/registry/unmapped/src/main.rs",
            CargoPresentationBypass::UnmappedPath,
        ),
        (
            "/__rabs/workspace/../other/src/main.rs",
            CargoPresentationBypass::InvalidRecord,
        ),
    ] {
        let mut original = diagnostic();
        original["message"]["spans"][0]["file_name"] = json!(path);
        assert_eq!(
            copy(&presentation(None), &line(&original)).0,
            CargoPresentationOutcome::Bypass(expected)
        );
    }
    let presenter = CargoJsonPresentation::new(mapping("/home/test/__rabs/out/cargo"), None);
    let (outcome, bytes) = copy(&presenter, &line(&diagnostic()));
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        output["message"]["spans"][0]["file_name"],
        "/home/test/__rabs/out/cargo/src/main.rs"
    );
    assert!(
        output["message"]["rendered"]
            .as_str()
            .unwrap()
            .contains(" --> /home/test/__rabs/out/cargo/src/main.rs:7:2")
    );
}

#[test]
fn rendered_locations_require_matching_spans_and_preserve_color_and_source_literals() {
    let mut original = diagnostic();
    original["message"]["rendered"] = json!(
        "\u{1b}[1;34m --> \u{1b}[0m/__rabs/workspace/src/main.rs\u{1b}[1m:7:2\u{1b}[0m\n7 | \"/__rabs/workspace/literal\"\n"
    );
    let (outcome, bytes) = copy(&presentation(None), &line(&original));
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    let output: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        output["message"]["rendered"],
        "\u{1b}[1;34m --> \u{1b}[0m/home/test/project/src/main.rs\u{1b}[1m:7:2\u{1b}[0m\n7 | \"/__rabs/workspace/literal\"\n"
    );
    original["message"]["rendered"] = json!(" --> /__rabs/workspace/src/elsewhere.rs:7:2\n");
    assert_eq!(
        copy(&presentation(None), &line(&original)).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::UnsupportedRenderedLocation)
    );
    original = diagnostic();
    original["message"]["message"] = json!("literal\n --> /__rabs/workspace/src/main.rs:7:2");
    assert_eq!(
        copy(&presentation(None), &line(&original)).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::UnsupportedRenderedLocation)
    );
    original = diagnostic();
    original["message"]["message"] =
        json!("literal\n\u{1b}[31m--> /__rabs/workspace/src/main.rs:7:2\u{1b}[0m");
    original["message"]["rendered"] = json!(
        "error: literal\n\u{1b}[31m--> /__rabs/workspace/src/main.rs:7:2\u{1b}[0m\n --> /__rabs/workspace/src/main.rs:7:2\n"
    );
    let (outcome, output) = copy(&presentation(None), &line(&original));
    assert_eq!(
        outcome,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::UnsupportedRenderedLocation)
    );
    assert!(
        output.is_empty(),
        "colored literal message text must never be rewritten as a location"
    );
}

struct SplitReader<'a> {
    bytes: &'a [u8],
    quantum: usize,
}

impl Read for SplitReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.len().min(output.len()).min(self.quantum);
        output[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}

#[test]
fn split_reads_crlf_and_build_finished_keep_runtime_bytes_opaque() {
    let mut bytes = line(&artifact());
    bytes.pop();
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(b"{ \"reason\": \"build-finished\", \"success\": true }\r\n");
    let runtime = b"\xff\0{\"reason\":\"compiler-artifact\",\"filenames\":[\"/__rabs/out/cargo/not-a-result\"]}\nno final newline";
    bytes.extend_from_slice(runtime);
    let presenter = presentation(Some(&["debug/fixture"]));
    let expected = copy(&presenter, &bytes).1;
    assert!(expected.ends_with(runtime));
    assert_eq!(expected.iter().filter(|byte| **byte == b'\r').count(), 2);
    for quantum in [1, 2, 7, 64, READ_BYTES] {
        let mut output = Vec::new();
        assert_eq!(
            presenter
                .copy(
                    SplitReader {
                        bytes: &bytes,
                        quantum
                    },
                    &mut output,
                    u64::MAX,
                    || Ok(())
                )
                .unwrap(),
            CargoPresentationOutcome::Complete
        );
        assert_eq!(output, expected, "read quantum {quantum}");
    }
}

#[test]
fn opaque_bytes_and_rustc_internal_events_are_byte_exact() {
    let original = b"plain \xff /__rabs/workspace/literal\r\n{ malformed /__rabs/workspace/literal\n{ \"artifact\":\"/__rabs/out/cargo/exact.rmeta\",\"emit\":\"metadata\" }\n{ \"reason\":\"application-event\",\"message\":\"/__rabs/workspace/literal\" }\n";
    let (outcome, output) = copy(&presentation(None), original);
    assert_eq!(outcome, CargoPresentationOutcome::Complete);
    assert_eq!(output, original);
}

#[test]
fn large_plain_and_runtime_lines_stream_but_json_and_expansion_have_bounds() {
    let opaque = vec![b'x'; MAX_JSON_BYTES + READ_BYTES];
    assert_eq!(
        copy(&presentation(None), &opaque),
        (CargoPresentationOutcome::Complete, opaque.clone())
    );
    let mut runtime = line(&json!({"reason":"build-finished", "success":false}));
    runtime.push(b'{');
    runtime.extend_from_slice(&opaque);
    assert_eq!(
        copy(&presentation(None), &runtime),
        (CargoPresentationOutcome::Complete, runtime.clone())
    );
    let mut oversized = vec![b'{'];
    oversized.extend_from_slice(&opaque);
    assert_eq!(
        copy(&presentation(None), &oversized).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::OversizedRecord)
    );
    let huge_mapping = CargoJsonPresentation::new(
        mapping(&format!("/{}", "a".repeat(MAX_TRANSLATED_BYTES))),
        None,
    );
    assert_eq!(
        copy(&huge_mapping, &line(&diagnostic())).0,
        CargoPresentationOutcome::Bypass(CargoPresentationBypass::OversizedTranslation)
    );
}

#[test]
fn cumulative_output_limit_charges_translated_opaque_and_runtime_bytes() {
    let presenter = presentation(Some(&["debug/fixture"]));
    let mut runtime = line(&json!({"reason":"build-finished", "success":true}));
    runtime.extend_from_slice(b"\xff\0opaque runtime without a final newline");
    for original in [
        b"abc\nsecond opaque line".to_vec(),
        b"{ \"application\": \"unknown-json-is-also-charged\" }\n".to_vec(),
        line(&artifact()),
        runtime,
    ] {
        let expected = copy(&presenter, &original).1;
        for quantum in [1, READ_BYTES] {
            let mut output = Vec::new();
            assert_eq!(
                presenter
                    .copy(
                        SplitReader {
                            bytes: &original,
                            quantum
                        },
                        &mut output,
                        expected.len() as u64,
                        || Ok(()),
                    )
                    .unwrap(),
                CargoPresentationOutcome::Complete
            );
            assert_eq!(output, expected);
            output.clear();
            let bound = expected.len() as u64 - 1;
            assert_eq!(
                presenter
                    .copy(
                        SplitReader {
                            bytes: &original,
                            quantum
                        },
                        &mut output,
                        bound,
                        || Ok(()),
                    )
                    .unwrap(),
                CargoPresentationOutcome::Bypass(CargoPresentationBypass::OutputLimit)
            );
            assert!(output.len() as u64 <= bound);
        }
    }
    assert_eq!(
        presenter
            .copy(&b""[..], &mut Vec::new(), 0, || Ok(()))
            .unwrap(),
        CargoPresentationOutcome::Complete
    );
}

#[test]
fn recognized_malformed_or_truncated_records_bypass_without_partial_record() {
    let mut malformed = artifact();
    malformed["filenames"] = json!([42]);
    for bytes in [
        line(&malformed),
        serde_json::to_vec(&artifact()).unwrap(),
        line(&json!({"reason":"build-finished", "success":"true"})),
    ] {
        let (outcome, output) = copy(&presentation(Some(&["debug/fixture"])), &bytes);
        assert_eq!(
            outcome,
            CargoPresentationOutcome::Bypass(CargoPresentationBypass::InvalidRecord)
        );
        assert!(output.is_empty());
    }
}

#[test]
fn cancellation_and_sink_failures_are_io_failures_not_presentation_bypass() {
    let error = presentation(None)
        .copy(&b"ordinary"[..], &mut Vec::new(), u64::MAX, || {
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    struct FailedSink;
    impl Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        presentation(None)
            .copy(&b"ordinary"[..], &mut FailedSink, u64::MAX, || Ok(()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}
