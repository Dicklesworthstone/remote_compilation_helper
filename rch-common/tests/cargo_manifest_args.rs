//! Public admission boundaries for Cargo's literal manifest option aliases.

use rch_common::admit_preflight::preflight;
use rch_common::cargo_args::parse_manifest_selection;
use rch_common::patterns::{
    CompilationKind, classify_command, classify_command_detailed, is_cargo_package_verification,
};

#[test]
fn manifest_operands_never_select_worker_capabilities() {
    for selector in [
        "--manifest-path '--target=x86_64-pc-windows-msvc'",
        "-m '--target=x86_64-pc-windows-msvc'",
        "-qm '--target=x86_64-pc-windows-msvc'",
        "-vvm=--target=x86_64-pc-windows-msvc",
        "-qmpath/to/Cargo.toml",
    ] {
        let command = format!("cargo build {selector} --target wasm32-unknown-unknown");
        let admitted = preflight(&command, true);
        assert!(admitted.is_compilation, "{command}");
        assert_eq!(
            admitted.required.needs_targets,
            ["wasm32-unknown-unknown"],
            "{command}"
        );
        assert_eq!(admitted.required.needs_os, None, "{command}");
    }
}

#[test]
fn expanding_attached_manifest_values_preserve_later_known_targets() {
    for selector in [
        "-m\"path/$MANIFEST\"",
        "-qm\"path/$MANIFEST\"",
        "-vvm=\"$MANIFEST\"",
        "-m \"$MANIFEST\"",
        "-qm \"$MANIFEST\"",
    ] {
        let command = format!("cargo check {selector} --target wasm32-unknown-unknown");
        assert_eq!(
            preflight(&command, true).required.needs_targets,
            ["wasm32-unknown-unknown"],
            "{command}"
        );
    }
    // This expansion can collapse to bare -m and consume the next argument.
    // No worker requirement may be invented from that ambiguous boundary.
    let command = "cargo check -qm\"$MANIFEST\" --target x86_64-pc-windows-msvc";
    assert!(preflight(command, true).required.needs_targets.is_empty());
}

#[test]
fn regression_cargo_package_short_manifest_options_preserve_verification() {
    for command in [
        "cargo package -m crates/app/Cargo.toml",
        "cargo package -mcrates/app/Cargo.toml",
        "cargo package -m=crates/app/Cargo.toml",
        "cargo package -qm crates/app/Cargo.toml",
        "cargo package -vvmcrates/app/Cargo.toml --locked",
        "cargo package -qm=crates/app/Cargo.toml --features=ansi",
        "cargo publish --dry-run -m crates/app/Cargo.toml",
        "cargo publish -mcrates/app/Cargo.toml --dry-run",
        "cargo publish -qnm=crates/app/Cargo.toml --locked",
        "cargo +nightly --offline publish -nmcrates/app/Cargo.toml",
        "env CARGO_INCREMENTAL=0 cargo publish -n -qm crates/app/Cargo.toml",
    ] {
        assert!(is_cargo_package_verification(command), "{command}");
        let classification = classify_command(command);
        assert!(
            classification.is_compilation,
            "{command}: {classification:?}"
        );
        assert_eq!(classification.kind, Some(CompilationKind::CargoBuild));
        assert_eq!(
            classify_command_detailed(command).classification,
            classification,
            "diagnosis must agree with execution for {command}"
        );
    }
}

#[test]
fn regression_cargo_package_short_manifest_options_cannot_authorize_publication() {
    for command in [
        "cargo publish -m crates/app/Cargo.toml",
        "cargo publish -qmcrates/app/Cargo.toml",
        "cargo publish -m=-n",
        "cargo publish -qm--dry-run",
        "cargo publish -qm --dry-run",
        "cargo publish --config -n -m crates/app/Cargo.toml",
        "cargo publish --config=-nmcrates/app/Cargo.toml",
        "cargo publish -F-nmcrates/app/Cargo.toml",
        "cargo publish -qF -n -m crates/app/Cargo.toml",
        "cargo publish -nmcrates/app/Cargo.toml --no-verify",
        "cargo package -lmcrates/app/Cargo.toml",
        "cargo package -hmcrates/app/Cargo.toml",
        "cargo package -Vmcrates/app/Cargo.toml",
        "cargo publish -nmcrates/app/Cargo.toml -- --no-verify",
        "cargo publish -- -nmcrates/app/Cargo.toml",
        "cargo package -m",
        "cargo package -qm=",
        "cargo package -qmcrates/app/Cargo.toml --manifest-path other/Cargo.toml",
        "cargo publish -n -mcrates/app/Cargo.toml -mOther.toml",
        "cargo publish -nmcrates/app/Cargo.toml --unknown-option",
    ] {
        assert!(!is_cargo_package_verification(command), "{command}");
        let classification = classify_command(command);
        assert!(
            !classification.is_compilation,
            "{command}: {classification:?}"
        );
        assert!(
            !classify_command_detailed(command)
                .classification
                .is_compilation,
            "{command}"
        );
    }
}

#[test]
fn nextest_option_operands_cannot_become_manifest_or_target_selectors() {
    for option in [
        "-E",
        "--filter-expr",
        "--filterset",
        "-P",
        "--profile",
        "--test-threads",
        "--status-level",
        "--archive-file",
    ] {
        let args = [
            "nextest",
            "run",
            option,
            "-qmdecoy/Cargo.toml",
            "-m",
            "actual/Cargo.toml",
        ]
        .map(str::to_owned);
        let selected = parse_manifest_selection(&args).unwrap();
        assert_eq!(selected.manifest.unwrap().value, "actual/Cargo.toml");
        let command = format!(
            "cargo nextest run {option} --target=x86_64-pc-windows-msvc -m actual/Cargo.toml --target wasm32-unknown-unknown"
        );
        let admitted = preflight(&command, true);
        assert_eq!(
            admitted.required.needs_targets,
            ["wasm32-unknown-unknown"],
            "{command}"
        );
        assert_eq!(admitted.required.needs_os, None, "{command}");
    }
}
