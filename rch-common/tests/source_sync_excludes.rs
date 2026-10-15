//! Conservative source-sync defaults (#109). The filesystem tests use real,
//! local rsync endpoints, not a worker or a simulated pattern interpreter.

use rch_common::TransferConfig;

#[test]
fn defaults_and_deserialization_share_agent_state_policy() {
    let direct = TransferConfig::default();
    let from_toml: TransferConfig = toml::from_str("").unwrap();
    let from_json: TransferConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(direct.exclude_patterns, from_toml.exclude_patterns);
    assert_eq!(direct.exclude_patterns, from_json.exclude_patterns);
    for pattern in [".ntm/", ".beads-recovery/", ".beads/"] {
        assert_eq!(
            direct
                .exclude_patterns
                .iter()
                .filter(|value| *value == pattern)
                .count(),
            1,
            "missing or duplicate directory-only default: {pattern}"
        );
    }
    for pattern in [
        "scratch/",
        "data/",
        "artifacts/",
        ".cargo/",
        ".claude/",
        ".ntm*",
        ".beads*",
    ] {
        assert!(
            !direct.exclude_patterns.iter().any(|value| value == pattern),
            "overbroad default would discard legitimate input: {pattern}"
        );
    }
}

#[test]
fn explicit_exclusion_lists_replace_defaults() {
    let custom: TransferConfig =
        toml::from_str("exclude_patterns = ['target/', '/scratch/session-only/']").unwrap();
    assert_eq!(
        custom.exclude_patterns,
        ["target/", "/scratch/session-only/"]
    );
    let empty: TransferConfig = toml::from_str("exclude_patterns = []").unwrap();
    assert!(empty.exclude_patterns.is_empty());
    let roundtrip: TransferConfig =
        serde_json::from_str(&serde_json::to_string(&custom).unwrap()).unwrap();
    assert_eq!(roundtrip.exclude_patterns, custom.exclude_patterns);
}

#[cfg(unix)]
mod rsync {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const EXCLUDED: &[&str] = &[
        ".ntm/sessions/state.json",
        ".beads-recovery/checkpoint.json",
        ".beads/.br_recovery/state.json",
        "nested/.ntm/sessions/state.json",
        "nested/.beads-recovery/checkpoint.json",
        "nested/.beads/.br_recovery/state.json",
        "nested/deep/.ntm/log.txt",
    ];
    const INCLUDED: &[&str] = &[
        "src/lib.rs",
        "src/name with spaces.rs",
        "src/literal[1].rs",
        "scratch/generated.rs",
        "data/input.txt",
        "artifacts/fixture.txt",
        ".cargo/config.toml",
        ".claude/settings.json",
        ".rch/config.toml",
        ".ntm-fixtures/input.txt",
        ".beads-recovery-tools/input.txt",
        "fixtures/files/.ntm",
        "fixtures/files/.beads-recovery",
    ];

    fn fixture() -> (PathBuf, PathBuf) {
        // Retain the small test-owned trees for diagnostics; never touch workers.
        let root = tempfile::tempdir().unwrap().keep();
        let source = root.join("source");
        for name in EXCLUDED.iter().chain(INCLUDED) {
            let path = source.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"build-input").unwrap();
        }
        (root, source)
    }

    fn command(source: &Path, destination: &Path, excludes: &[String]) -> Command {
        let mut command = Command::new("rsync");
        command.args(["-a", "--no-owner", "--no-group", "--timeout=10"]);
        for pattern in excludes {
            command.arg("--exclude").arg(pattern);
        }
        command
            .arg(format!("{}/", source.display()))
            .arg(format!("{}/", destination.display()));
        command
    }

    fn output(command: &mut Command) -> String {
        let output = command.output().expect("source-sync tests require rsync");
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "{command:?}: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn selected(source: &Path, destination: &Path, excludes: &[String]) -> BTreeSet<String> {
        let mut command = command(source, destination, excludes);
        command.args(["--dry-run", "--itemize-changes", "--out-format=%i\t%n"]);
        output(&mut command)
            .lines()
            .filter_map(|line| {
                let (item, path) = line.split_once('\t')?;
                (item.as_bytes().get(1) == Some(&b'f'))
                    .then(|| path.strip_prefix("./").unwrap_or(path).to_owned())
            })
            .collect()
    }

    #[test]
    fn nested_agent_directories_are_not_selected_but_legitimate_inputs_are() {
        let (root, source) = fixture();
        let destination = root.join("not-created");
        assert_eq!(
            selected(
                &source,
                &destination,
                &TransferConfig::default().exclude_patterns
            ),
            INCLUDED.iter().map(|name| (*name).to_owned()).collect()
        );
        assert!(!destination.exists(), "selection must be read-only");
        for name in EXCLUDED {
            assert_eq!(fs::read(source.join(name)).unwrap(), b"build-input");
        }
        // An explicit configuration exception must also work at nested depths.
        let custom: TransferConfig = toml::from_str("exclude_patterns = ['target/']").unwrap();
        assert_eq!(
            selected(&source, &destination, &custom.exclude_patterns),
            INCLUDED
                .iter()
                .chain(EXCLUDED)
                .map(|name| (*name).to_owned())
                .collect()
        );
    }

    #[test]
    fn both_upload_variants_preserve_preexisting_excluded_destination_files() {
        let (root, source) = fixture();
        let excludes = TransferConfig::default().exclude_patterns;
        for streaming in [false, true] {
            let destination = root.join(format!("destination-{streaming}"));
            for name in EXCLUDED {
                let path = destination.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"retained-worker-state").unwrap();
            }
            let mut upload = command(&source, &destination, &excludes);
            upload.args(["--delete", "--partial", "--partial-dir=.rch-partial"]);
            upload.arg(if streaming { "--progress" } else { "--stats" });
            output(&mut upload);
            for name in INCLUDED {
                assert_eq!(fs::read(destination.join(name)).unwrap(), b"build-input");
            }
            for name in EXCLUDED {
                assert_eq!(
                    fs::read(destination.join(name)).unwrap(),
                    b"retained-worker-state"
                );
                assert_eq!(fs::read(source.join(name)).unwrap(), b"build-input");
            }
        }
    }

    #[test]
    fn checksum_barrier_ignores_state_churn_but_detects_same_metadata_source_change() {
        let (root, source) = fixture();
        let destination = root.join("destination");
        let excludes = TransferConfig::default().exclude_patterns;
        output(&mut command(&source, &destination, &excludes));
        for name in EXCLUDED {
            fs::write(source.join(name), b"new-session-state").unwrap();
        }
        let barrier = || {
            let mut barrier = command(&source, &destination, &excludes);
            barrier.args([
                "--dry-run",
                "--checksum",
                "--delete",
                "--itemize-changes",
                "--out-format=%i\t%n",
            ]);
            output(&mut barrier)
        };
        // Only directory metadata can vary; no selected file or deletion delta.
        assert!(barrier().lines().all(|line| line.starts_with(".d")));
        let path = source.join("src/lib.rs");
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        fs::write(&path, b"stale-input").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert!(barrier().lines().any(|line| line.ends_with("\tsrc/lib.rs")));
        assert_eq!(
            fs::read(destination.join("src/lib.rs")).unwrap(),
            b"build-input"
        );
    }
}
