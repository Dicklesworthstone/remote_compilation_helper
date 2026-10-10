//! Literal argv admission, not shell evaluation or a substitute compiler.

use super::*;
use crate::hook::cargo_output_contract::CargoOutputCapture;

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn quoted_manifest_features_and_target_dir_keep_exact_argument_boundaries() {
    for command in [
        r#"cargo build --bin 'app' --manifest-path 'crates/space λ/Cargo.toml' --target-dir "target tree" --features 'first second'"#,
        r#"cargo build --bin ap''p --manifest-path crates/space\ λ/Cargo.toml --target-dir target\ tree --features "first second""#,
    ] {
        assert_eq!(
            build_arguments(CompilationKind::CargoBuild, command).unwrap(),
            strings(&[
                "--bin",
                "app",
                "--manifest-path",
                "crates/space λ/Cargo.toml",
                "--target-dir",
                "target tree",
                "--features",
                "first second",
            ]),
            "{command}"
        );
        let selected = selection(Some(CompilationKind::CargoBuild), command).unwrap();
        assert_eq!(selected.bins, BTreeSet::from(["app".to_owned()]));
    }
}

#[test]
fn exec_requoting_round_trips_literal_quotes_backslashes_and_dollar_bytes() {
    for manifest in [
        "crates/space λ/Cargo.toml",
        "crates/it's a package/Cargo.toml",
        "crates/double\"quote/Cargo.toml",
        "crates/back\\slash/Cargo.toml",
        "crates/literal $HOME $(printf not-executed)/Cargo.toml",
        "crates/literal [glob]*?;|&<>/Cargo.toml",
    ] {
        let argv = strings(&[
            "cargo",
            "build",
            "--bin=app",
            "--manifest-path",
            manifest,
            "--message-format=json,json-render-diagnostics",
        ]);
        let command = crate::hook::join_exec_command(&argv);
        assert_eq!(
            build_arguments(CompilationKind::CargoBuild, &command).unwrap(),
            argv[2..].to_vec(),
            "{command}"
        );
        let capture = CargoOutputCapture::for_command(Some(CompilationKind::CargoBuild), &command)
            .unwrap();
        assert!(capture.caller_json_supported());
        assert_eq!(capture.execution_command(&command), command);
    }
}

#[test]
fn quoted_wrapper_values_never_become_cargo_options() {
    let command = r#"env -u RUSTFLAGS -- CARGO_TARGET_DIR='target --bin decoy' rustup run nightly '/opt/tool chain/cargo' b '--bin=app' --features 'first --bin decoy' --profile 'lean'"#;
    let selected = selection(Some(CompilationKind::CargoBuild), command).unwrap();
    assert_eq!(selected.bins, BTreeSet::from(["app".to_owned()]));
    assert_eq!(selected.profile, "lean");
    let inline = r#"CARGO_TARGET_DIR='target tree' cargo +nightly b --bin "app" --manifest-path 'path --bin decoy/Cargo.toml'"#;
    let selected = selection(Some(CompilationKind::CargoBuild), inline).unwrap();
    assert_eq!(selected.bins, BTreeSet::from(["app".to_owned()]));
    for command in [
        "env -C 'another root' cargo build --bin app",
        "env --chdir='another root' cargo build --bin app",
        "time -p cargo build --bin app",
        "rustup run --install nightly cargo build --bin app",
        "sh -c 'cargo build --bin app'",
        "cargo-xwin build --bin app",
    ] {
        assert!(
            selection(Some(CompilationKind::CargoBuild), command).is_none(),
            "expanded the wrapper grammar: {command}"
        );
    }
}

#[test]
fn quoted_named_outputs_keep_the_existing_transfer_policy() {
    let plain = "cargo build --bin app --example demo-lib --profile lean --target x86_64-unknown-linux-gnu";
    let quoted = r#"cargo build '--bin=app' --example 'demo-lib' --profile "lean" --target='x86_64-unknown-linux-gnu' --manifest-path 'source tree/Cargo.toml'"#;
    let kind = Some(CompilationKind::CargoBuild);
    assert_eq!(patterns(kind, Some(plain)), patterns(kind, Some(quoted)));
    assert_eq!(
        super::super::get_custom_target_artifact_patterns(kind, Some(plain)),
        super::super::get_custom_target_artifact_patterns(kind, Some(quoted))
    );
    assert!(super::super::get_project_artifact_patterns(kind, Some(quoted), true).is_empty());
}

#[test]
fn quoting_does_not_admit_evaluation_comments_or_additional_outputs() {
    for command in [
        "cargo build --bin \"$APP\"",
        "cargo build --bin app --manifest-path \"$ROOT/Cargo.toml\"",
        "cargo build --bin app --manifest-path $(printf Cargo.toml)",
        "cargo build --bin app --manifest-path `printf Cargo.toml`",
        "cargo build --bin app --manifest-path ~/Cargo.toml",
        "cargo build --bin app --manifest-path crates/*/Cargo.toml",
        "cargo build --bin app; cargo build --bin other",
        "cargo build --bin app && cargo build --bin other",
        "cargo build --bin app | cat",
        "cargo build --bin app > result",
        "cargo build --bin app # --lib",
        "cargo build --bin app --features '{a,b}'",
        "cargo build --bin 'app*'",
        "cargo build --bin '../app'",
        "cargo build --bin app '--all-targets'",
        "cargo build --bin app '--config=build.target=custom.json'",
        "cargo build --bin app '--'",
        "cargo build --bin app --manifest-path 'unfinished",
        "cargo build --bin app --manifest-path unfinished\\",
        "cargo build --bin app\ncargo build --bin other",
        "cargo build --bin app --manifest-path 'line\nfeed/Cargo.toml'",
        "cargo build --bin app --manifest-path 'tab\tpath/Cargo.toml'",
        "cargo build --bin app --manifest-path 'carriage\rreturn'",
        "cargo build --bin app --manifest-path 'nul\0byte'",
        "cargo build --bin app --manifest-path 'control\u{85}byte'",
    ] {
        assert!(
            selection(Some(CompilationKind::CargoBuild), command).is_none(),
            "admitted unsupported syntax: {command:?}"
        );
    }
    // Whitespace between words is not a control byte inside a path.
    assert!(selection(Some(CompilationKind::CargoBuild), "cargo\tbuild\t--bin\t'app'").is_some());
}

#[test]
fn quoted_opaque_values_cannot_supply_a_missing_target_or_mode() {
    for (kind, command) in [
        (
            CompilationKind::CargoBuild,
            "cargo build --features 'first --bin app'",
        ),
        (
            CompilationKind::CargoBuild,
            "cargo build --bin app --package '--bin decoy'",
        ),
        (
            CompilationKind::CargoTest,
            "cargo test --test alpha --features '--no-run'",
        ),
        (
            CompilationKind::CargoTest,
            "cargo test --test alpha --features 'first --no-run'",
        ),
        (
            CompilationKind::CargoTest,
            "cargo test --test alpha -- '--no-run'",
        ),
        (
            CompilationKind::CargoBench,
            "cargo bench --bench alpha --features 'first --no-run'",
        ),
    ] {
        assert!(selection(Some(kind), command).is_none(), "{command}");
    }
}

#[test]
fn quoted_commands_retain_byte_and_word_budgets() {
    let too_long = format!("cargo build --bin app --manifest-path '{}'", "λ".repeat(32_768));
    assert!(selection(Some(CompilationKind::CargoBuild), &too_long).is_none());
    let too_many = format!("cargo build --bin app {}", "'-q' ".repeat(4093));
    assert!(selection(Some(CompilationKind::CargoBuild), &too_many).is_none());
    let boundary = format!("cargo build --bin app {}", "'-q' ".repeat(4092));
    assert!(selection(Some(CompilationKind::CargoBuild), &boundary).is_some());
}

#[test]
fn quoted_no_run_capture_survives_serialization_without_widening_its_mode() {
    for (kind, subcommand, selector) in [
        (CompilationKind::CargoTest, "test", "test"),
        (CompilationKind::CargoBench, "bench", "bench"),
    ] {
        let command = format!(
            "cargo {subcommand} '--no-run' --{selector} 'alpha' --manifest-path 'source λ/Cargo.toml' --message-format 'json,json-render-diagnostics'"
        );
        let capture = CargoOutputCapture::for_command(Some(kind), &command).unwrap();
        assert!(capture.caller_json_supported());
        let restored: CargoOutputCapture =
            serde_json::from_slice(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(restored, capture);
        assert_eq!(restored.execution_command(&command), command);
        let executable = "/worker/target λ/deps/alpha-0123456789abcdef";
        let record = serde_json::json!({
            "reason": "compiler-artifact",
            "target": {"name": "alpha", "kind": [selector]},
            "filenames": [executable], "executable": executable, "fresh": true,
            "profile": {"test": true},
        });
        let receipt = format!("{record}\n{{\"reason\":\"build-finished\",\"success\":true}}\n");
        let contract = restored
            .parse_receipt(receipt.as_bytes(), Path::new("/worker/target λ"))
            .unwrap();
        assert_eq!(
            contract.required_files,
            BTreeSet::from([std::path::PathBuf::from("deps/alpha-0123456789abcdef")])
        );
        assert!(
            CargoOutputCapture::for_command(Some(kind), &command.replace("'--no-run'", ""))
                .is_none()
        );
        assert!(
            CargoOutputCapture::for_command(Some(kind), &command.replace("'alpha'", "'alpha*'"))
                .is_none()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn decoded_arguments_agree_with_a_real_shell_without_running_a_compiler() {
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::process::Command;

    for (words, suffix) in [
        (
            r#"cargo build --bin ap''p --manifest-path 'it'\''s λ/Cargo.toml' --features "first second""#,
            strings(&[
                "--bin", "app", "--manifest-path", "it's λ/Cargo.toml", "--features", "first second",
            ]),
        ),
        (
            r#"cargo build '--bin=app' --manifest-path 'literal $HOME $(printf not-executed)/Cargo.toml'"#,
            strings(&[
                "--bin=app",
                "--manifest-path",
                "literal $HOME $(printf not-executed)/Cargo.toml",
            ]),
        ),
        (
            r#"cargo build --bin app --manifest-path back\\slash/Cargo.toml --target-dir target\ tree"#,
            strings(&[
                "--bin", "app", "--manifest-path", "back\\slash/Cargo.toml", "--target-dir", "target tree",
            ]),
        ),
    ] {
        // Fixed fixture words only. `set --` records the shell's own argv
        // interpretation; it does not invoke Cargo, a worker, or a fake compiler.
        let script = format!("set -- {words}; shift 2; printf '%s\\0' \"$@\"");
        let mut shell = Command::new("/bin/sh");
        shell
            .arg("-c")
            .arg(script)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), shell.output())
            .await
            .expect("literal argv shell fixture timed out")
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        let expected: Vec<u8> = suffix
            .iter()
            .flat_map(|word| word.as_bytes().iter().copied().chain(std::iter::once(0)))
            .collect();
        assert_eq!(output.stdout, expected, "{words}");
        assert_eq!(
            build_arguments(CompilationKind::CargoBuild, words).unwrap(),
            suffix
        );
    }
}
