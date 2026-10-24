//! Validate the selected namespace before creating a Windows upload manifest.
//!
//! Win32 device names and trailing-dot/space aliases must not turn selected
//! source names into different receiver paths. ASCII case aliases and a file
//! or symlink used as another member's parent are refused as a whole batch.
//! Unicode names are preserved; this is not a claim to emulate every Windows
//! filesystem's Unicode collation, existing 8.3 aliases or reparse points.

use super::{Kind, Member};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
    {
        return false;
    }
    // Device names stay reserved with an extension and at nested depths.
    // Windows also recognizes superscript 1, 2 and 3 in COM/LPT names.
    // https://learn.microsoft.com/windows/win32/fileio/naming-a-file
    let stem = component.split('.').next().unwrap_or(component);
    let stem = stem.trim_end_matches(' ').to_ascii_lowercase();
    if matches!(stem.as_str(), "con" | "prn" | "aux" | "nul") {
        return false;
    }
    !stem
        .strip_prefix("com")
        .or_else(|| stem.strip_prefix("lpt"))
        .is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        })
}

/// Validate every member AND each implied parent before writing any manifest.
/// Never rename, discard, or merge a selected file to make it fit the worker.
pub(super) fn validate(members: &[Member]) -> Result<()> {
    let mut explicit = BTreeSet::new();
    let mut namespace: BTreeMap<String, (String, Kind)> = BTreeMap::new();
    for member in members {
        let path = member.path.to_str().context("non-UTF-8 archive member")?;
        anyhow::ensure!(explicit.insert(path), "duplicate Windows source member: {path:?}");
        let mut components = path.split('/').peekable();
        let mut prefix = String::new();
        while let Some(component) = components.next() {
            anyhow::ensure!(
                valid_component(component),
                "source filename cannot be represented on a Windows worker: {path:?}"
            );
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let kind = if components.peek().is_some() {
                Kind::Directory
            } else {
                member.kind
            };
            let key = prefix.to_ascii_lowercase();
            if let Some((original, previous_kind)) = namespace.get(&key) {
                anyhow::ensure!(
                    original == &prefix && *previous_kind == kind,
                    "selected source namespace aliases or conflicts on Windows: {original:?} and {prefix:?}"
                );
            } else {
                namespace.insert(key, (prefix.clone(), kind));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn member(path: &str, kind: Kind) -> Member {
        Member { path: PathBuf::from(path), kind }
    }

    #[test]
    fn ordinary_sources_unicode_and_agent_named_files_remain_eligible() {
        let members = [
            "src/name with spaces.rs", "src/literal[1].rs", "src/雪.rs", "src/-C",
            "scratch/generated.rs", "data/input.bin", "artifacts/fixture.txt",
            ".cargo/config.toml", ".claude/settings.json", "fixtures/.ntm",
            "fixtures/.beads-recovery", ".ntm-fixtures/input", "devices/COM0.rs",
            "devices/COM10.rs", "devices/nulled.txt", "devices/LPT12.rs",
        ].map(|path| member(path, Kind::File));
        validate(&members).unwrap();
        let mut with_directories = members.to_vec();
        with_directories.push(member("src", Kind::Directory));
        with_directories.push(member("empty", Kind::Directory));
        with_directories.push(member("src/link.rs", Kind::Symlink));
        validate(&with_directories).unwrap();
        with_directories.reverse();
        validate(&with_directories).unwrap();
    }

    #[test]
    fn device_aliases_with_extensions_are_refused_at_every_depth() {
        for device in [
            "CON", "prn", "Aux", "NUL", "COM1", "COM9", "LPT1", "LPT9",
            "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
        ] {
            for prefix in ["", "nested/deep/"] {
                for suffix in ["", ".txt", ".tar.gz", " .txt"] {
                    let name = format!("{prefix}{device}{suffix}");
                    for kind in [Kind::File, Kind::Directory, Kind::Symlink] {
                        assert!(validate(&[member(&name, kind)]).is_err(), "{name:?}");
                    }
                    assert!(validate(&[member(&format!("{name}/child"), Kind::File)]).is_err());
                }
            }
        }
    }

    #[test]
    fn invalid_components_refuse_without_normalizing_the_name() {
        for path in [
            "", "/absolute", "../outside", "a/../b", "a/./b", "a//b", "a/",
            "src/name.", "src/name ", "src/parent./child", "src/parent /child",
            r"src/a\b", "src/a:stream", "src/a<b", "src/a>b", "src/a\"b",
            "src/a|b", "src/a?b", "src/a*b", "src/a\nb", "src/a\0b",
        ] {
            assert!(validate(&[member(path, Kind::File)]).is_err(), "{path:?}");
        }
    }

    #[test]
    fn case_aliases_are_detected_in_leaves_and_implied_parents() {
        for (left, right) in [
            ("src/Lib.rs", "src/lib.rs"),
            ("Src/one.rs", "src/two.rs"),
            ("src/deep/one", "src/Deep/two"),
        ] {
            let mut members = vec![member(left, Kind::File), member(right, Kind::File)];
            assert!(validate(&members).is_err(), "{left} versus {right}");
            members.reverse();
            assert!(validate(&members).is_err(), "reverse {left} versus {right}");
        }
    }

    #[test]
    fn files_and_links_cannot_be_selected_ancestors_in_either_order() {
        for kind in [Kind::File, Kind::Symlink] {
            let mut members = vec![member("parent", kind), member("parent/child", Kind::File)];
            assert!(validate(&members).is_err());
            members.reverse();
            assert!(validate(&members).is_err());
        }
        assert!(validate(&[member("same", Kind::File), member("same", Kind::File)]).is_err());
    }

    #[test]
    fn explicit_agent_state_exception_does_not_become_an_extra_exclusion() {
        validate(&[
            member(".ntm", Kind::Directory),
            member(".ntm/session.json", Kind::File),
            member("nested/.beads-recovery/input.txt", Kind::File),
            member("fixtures/.beads-recovery", Kind::File),
        ]).unwrap();
    }

    #[tokio::test]
    async fn manifest_rejects_collisions_without_weakening_posix_receipts() {
        let selected = super::super::parse_members(
            b">f+++++++++\tsrc/File.rs\n>f+++++++++\tsrc/file.rs\n",
        ).unwrap();
        let paths = super::super::regular_paths(selected.clone()).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(super::super::validate_windows_paths(&paths).is_err());
        assert!(super::super::manifest(&selected).await.is_err());
        let mut late_invalid = vec![member("src/valid.rs", Kind::File)];
        late_invalid.push(member("nested/NUL.txt", Kind::File));
        assert!(super::super::manifest(&late_invalid).await.is_err());
    }

    #[tokio::test]
    async fn valid_manifest_keeps_exact_names_and_explicit_exceptions() {
        let members = vec![
            member("src", Kind::Directory),
            member("src/雪.rs", Kind::File),
            member("src/link.rs", Kind::Symlink),
            member(".ntm/fixture.json", Kind::File),
        ];
        let (manifest, files) = super::super::manifest(&members).await.unwrap();
        assert_eq!(files, 2);
        assert_eq!(
            std::fs::read(manifest.path()).unwrap(),
            "./src\0./src/雪.rs\0./src/link.rs\0./.ntm/fixture.json\0".as_bytes(),
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_windows_overlay_refuses_unrepresentable_selected_names() {
        use crate::transfer::{TransferPipeline, WorkerPlatform};
        use rch_common::TransferConfig;

        let retained = tempfile::tempdir().unwrap().keep();
        for (index, names) in [
            vec!["src/File.rs", "src/file.rs"],
            vec!["src/NUL.txt"],
            vec!["src/trailing."],
        ].into_iter().enumerate() {
            let root = retained.join(format!("case-{index}"));
            std::fs::create_dir_all(root.join("src")).unwrap();
            for name in &names {
                std::fs::write(root.join(name), b"selected source").unwrap();
            }
            let mut pipeline = TransferPipeline::new(
                root.clone(), "windows-overlay-namespace".to_owned(),
                "abcdef0123456789".to_owned(), TransferConfig::default(),
            );
            pipeline.worker_platform = WorkerPlatform::Windows;
            pipeline.sync_include_patterns = Some(vec!["/src/".to_owned(), "/src/**".to_owned()]);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10), pipeline.selected_source_archive(),
            ).await.expect("local source selection timed out");
            assert!(result.is_err(), "unrepresentable overlay was archived: {names:?}");
            for name in names {
                assert_eq!(std::fs::read(root.join(name)).unwrap(), b"selected source");
            }
        }
    }
}
